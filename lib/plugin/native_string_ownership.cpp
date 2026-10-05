#include "obf/plugin/internal/native_string_ownership.h"

#include "obf/plugin/obfuscator_plugin_internal.h"
#include "obf/support/constant_materialization.h"
#include "obf/support/stable_hash.h"
#include "obf/transforms/string_encoding.h"
#include "obf/vm/virtualize.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Mangler.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/ValueHandle.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace obf {
namespace {

enum class definition_kind { plaintext, forward, non_string, protected_string, unknown };

llvm::StringRef kind_name(definition_kind kind) {
  switch (kind) {
    case definition_kind::plaintext: return "plaintext";
    case definition_kind::forward: return "forward";
    case definition_kind::non_string: return "non_string";
    case definition_kind::protected_string: return "protected";
    case definition_kind::unknown: return "unknown";
  }
  llvm_unreachable("invalid native ownership definition kind");
}

bool is_metadata_global(const llvm::GlobalValue& value) {
  if (value.getName().starts_with("llvm.")) { return true; }
  const auto* global = llvm::dyn_cast<llvm::GlobalVariable>(&value);
  return global != nullptr && global->hasSection() && global->getSection() == "llvm.metadata";
}

bool is_generated_binary(const llvm::GlobalVariable& global) {
  const support::encoded_data_kind kind = support::get_encoded_data_kind(global);
  const bool bytecode = vm::has_encoded_bytecode_payload(global);
  if (bytecode && kind != support::encoded_data_kind::none) {
    llvm::report_fatal_error("conflicting encoded data provenance");
  }
  return bytecode || kind == support::encoded_data_kind::ciphertext ||
         kind == support::encoded_data_kind::build_key;
}

// Only an address expression, not a loaded pointer or arbitrary constant
// expression, can establish a one-level static forwarding edge.
const llvm::GlobalValue* pointer_target(const llvm::Constant& constant) {
  if (const auto* global = llvm::dyn_cast<llvm::GlobalValue>(&constant)) { return global; }
  const auto* expression = llvm::dyn_cast<llvm::ConstantExpr>(&constant);
  if (expression == nullptr ||
      (!expression->isCast() && expression->getOpcode() != llvm::Instruction::GetElementPtr)) {
    return nullptr;
  }
  if (!expression->getType()->isPointerTy() || !expression->getOperand(0)->getType()->isPointerTy()) {
    return nullptr;
  }
  return pointer_target(*llvm::cast<llvm::Constant>(expression->getOperand(0)));
}

bool is_numeric_type(const llvm::Type& type) {
  if (type.isIntegerTy() || type.isFloatingPointTy()) { return true; }
  if (const auto* array = llvm::dyn_cast<llvm::ArrayType>(&type)) {
    return is_numeric_type(*array->getElementType());
  }
  if (const auto* vector = llvm::dyn_cast<llvm::VectorType>(&type)) {
    return is_numeric_type(*vector->getElementType());
  }
  if (const auto* structure = llvm::dyn_cast<llvm::StructType>(&type)) {
    return !structure->isOpaque() &&
           llvm::all_of(structure->elements(),
                        [](const llvm::Type* field) { return is_numeric_type(*field); });
  }
  return false;
}

bool is_numeric_initializer(const llvm::Constant& constant) {
  if (llvm::isa<llvm::ConstantInt, llvm::ConstantFP>(constant)) { return true; }
  if (!is_numeric_type(*constant.getType())) { return false; }
  if (llvm::isa<llvm::ConstantAggregateZero, llvm::ConstantDataSequential>(constant)) { return true; }
  if (!llvm::isa<llvm::ConstantArray, llvm::ConstantStruct, llvm::ConstantVector>(constant)) {
    return false;
  }
  return llvm::all_of(constant.operands(), [](const llvm::Use& operand) {
    return is_numeric_initializer(*llvm::cast<llvm::Constant>(operand.get()));
  });
}

void append_little_endian(std::string& bytes, std::uint64_t value, unsigned width) {
  for (unsigned index = 0; index < width; ++index) {
    bytes.push_back(static_cast<char>((value >> (8 * index)) & 0xff));
  }
}

void append_entry(std::string& payload, unsigned kind, llvm::json::Object body) {
  std::string json;
  llvm::raw_string_ostream stream(json);
  stream << llvm::json::Value(std::move(body));
  stream.flush();
  if (json.size() > std::numeric_limits<std::uint32_t>::max()) {
    llvm::report_fatal_error("native string ownership entry exceeds object record limit");
  }
  append_little_endian(payload, json.size(), 4);
  append_little_endian(payload, kind, 2);
  append_little_endian(payload, 0, 2);
  payload += json;
}

}  // namespace

struct native_string_ownership::snapshot {
  struct identity {
    llvm::WeakVH value;
    std::string original_name;
    bool erased_by_strong_encoding = false;
    bool has_definition = false;
  };
  struct reader {
    unsigned owner;
    llvm::SmallVector<unsigned, 8> dependencies;
  };
  struct definition {
    unsigned symbol;
    definition_kind kind;
    llvm::SmallVector<unsigned, 4> targets;
    bool strong_encoding = false;
    bool authenticated_destination = false;
  };

  std::vector<identity> identities;
  std::vector<reader> readers;
  std::vector<definition> definitions;
  llvm::DenseMap<const llvm::GlobalValue*, unsigned> identity_indices;
  std::uint64_t module_id = 0;

  unsigned identify(llvm::GlobalValue& value) {
    const auto found = identity_indices.find(&value);
    if (found != identity_indices.end() &&
        static_cast<llvm::Value*>(identities[found->second].value) == &value) {
      return found->second;
    }
    const unsigned index = identities.size();
    identities.push_back({llvm::WeakVH(&value), value.getName().str(), false, false});
    identity_indices[&value] = index;
    return index;
  }

  bool classify_pointer(const llvm::Constant& pointer, definition& record) {
    if (llvm::isa<llvm::ConstantPointerNull>(pointer)) { return true; }
    const llvm::GlobalValue* target = pointer_target(pointer);
    if (target == nullptr) { return false; }
    if (llvm::isa<llvm::Function>(target)) { return true; }
    if (is_metadata_global(*target)) { return false; }
    const unsigned index = identify(*const_cast<llvm::GlobalValue*>(target));
    if (!llvm::is_contained(record.targets, index)) { record.targets.push_back(index); }
    return true;
  }

  void classify_definition(llvm::GlobalValue& value) {
    definition record{identify(value), definition_kind::unknown, {}, false};
    const llvm::Constant* initializer = nullptr;
    if (auto* global = llvm::dyn_cast<llvm::GlobalVariable>(&value)) {
      if (is_generated_binary(*global)) {
        record.kind = definition_kind::non_string;
      } else if (is_source_string_candidate(*global)) {
        record.kind = definition_kind::plaintext;
      } else if (support::get_encoded_data_kind(*global) == support::encoded_data_kind::local_string) {
        // An ordinary VM transform is not proof of strong ownership.
        record.kind = definition_kind::unknown;
      } else {
        initializer = global->getInitializer();
      }
    } else if (auto* alias = llvm::dyn_cast<llvm::GlobalAlias>(&value)) {
      // A data alias identifies its own object bytes, not necessarily the
      // prevailing definition of its aliasee's name (notably for weak data).
      // Alias expressions are outside the one-level cell/table contract.
      // Preserve the reader's alias dependency and leave its data provenance
      // unknown rather than forwarding through linker symbol resolution.
      if (alias->getValueType()->isFunctionTy() &&
          llvm::isa_and_nonnull<llvm::Function>(pointer_target(*alias->getAliasee()))) {
        record.kind = definition_kind::non_string;
      }
    }
    if (initializer != nullptr) {
      if (initializer->getType()->isPointerTy()) {
        if (classify_pointer(*initializer, record)) {
          record.kind = record.targets.empty() ? definition_kind::non_string : definition_kind::forward;
        }
      } else if (const auto* type = llvm::dyn_cast<llvm::ArrayType>(initializer->getType());
                 type != nullptr && type->getElementType()->isPointerTy()) {
        bool known = true;
        if (llvm::isa<llvm::ConstantAggregateZero>(initializer)) {
          record.kind = definition_kind::non_string;
        } else if (const auto* table = llvm::dyn_cast<llvm::ConstantArray>(initializer)) {
          for (const llvm::Use& entry : table->operands()) {
            known &= classify_pointer(*llvm::cast<llvm::Constant>(entry.get()), record);
          }
          if (known) {
            record.kind = record.targets.empty() ? definition_kind::non_string : definition_kind::forward;
          }
        }
      } else if (is_numeric_initializer(*initializer)) {
        record.kind = definition_kind::non_string;
      }
    }
    if (record.kind != definition_kind::forward) { record.targets.clear(); }
    identities[record.symbol].has_definition = true;
    definitions.push_back(std::move(record));
  }

  void collect_dependencies(const llvm::Value& operand,
                            llvm::SmallPtrSetImpl<const llvm::Value*>& visited,
                            reader& record) {
    if (!visited.insert(&operand).second) { return; }
    if (const auto* global = llvm::dyn_cast<llvm::GlobalValue>(&operand)) {
      if (llvm::isa<llvm::Function>(global) || is_metadata_global(*global)) { return; }
      const unsigned index = identify(*const_cast<llvm::GlobalValue*>(global));
      if (!llvm::is_contained(record.dependencies, index)) { record.dependencies.push_back(index); }
      return;
    }
    // Instructions are visited individually; descending into arbitrary SSA
    // values would confuse caller argument buffers with static dependencies.
    const auto* constant = llvm::dyn_cast<llvm::Constant>(&operand);
    if (constant == nullptr) { return; }
    for (const llvm::Use& child : constant->operands()) {
      collect_dependencies(*child.get(), visited, record);
    }
  }

  llvm::GlobalValue* live_value(unsigned index) const {
    return llvm::dyn_cast_or_null<llvm::GlobalValue>(static_cast<llvm::Value*>(identities[index].value));
  }

  bool omit_erased(unsigned index) const {
    if (live_value(index) != nullptr) { return false; }
    if (identities[index].erased_by_strong_encoding) { return true; }
    llvm::report_fatal_error(llvm::Twine("native string ownership lost original dependency '") +
                            identities[index].original_name + "' without strong encoding proof");
  }
};

native_string_ownership::native_string_ownership(
    llvm::Module& module, llvm::ArrayRef<function_pipeline_state> states, bool native_route) {
  const llvm::Triple triple(module.getTargetTriple());
  if (!native_route || (!triple.isOSBinFormatELF() && !triple.isOSBinFormatCOFF()) ||
      module.getNamedMetadata("obf.native.ownership.emitted") != nullptr) {
    return;
  }
  snapshot_ = std::make_unique<snapshot>();
  snapshot_->module_id = stable_hash_string(module.getModuleIdentifier(),
                                            stable_hash_string(module.getSourceFileName()));
  // Give anonymous source objects unique identities before the string emitter
  // reports outcomes by name. Final cleanup can still rename these objects.
  std::uint64_t anonymous_ordinal = 0;
  for (llvm::GlobalVariable& global : module.globals()) {
    if (!global.hasName() && !global.isDeclarationForLinker()) {
      global.setName((llvm::Twine("ns_") + llvm::Twine(snapshot_->module_id) + "_" +
                      llvm::Twine(anonymous_ordinal++)).str());
    }
  }
  for (llvm::GlobalVariable& global : module.globals()) {
    if (!global.isDeclarationForLinker() && !is_metadata_global(global)) {
      snapshot_->classify_definition(global);
    }
  }
  for (llvm::GlobalAlias& alias : module.aliases()) {
    if (!alias.isDeclarationForLinker() && !is_metadata_global(alias)) {
      snapshot_->classify_definition(alias);
    }
  }
  for (const function_pipeline_state& state : states) {
    llvm::Function* function = state.function;
    if (function == nullptr || function->isDeclarationForLinker() ||
        state.report.decision.policy.level != protection_level::strong_vm) {
      continue;
    }
    snapshot::reader record{snapshot_->identify(*function), {}};
    llvm::SmallPtrSet<const llvm::Value*, 32> visited;
    for (const llvm::BasicBlock& block : *function) {
      for (const llvm::Instruction& instruction : block) {
        for (const llvm::Use& operand : instruction.operands()) {
          snapshot_->collect_dependencies(*operand.get(), visited, record);
        }
      }
    }
    snapshot_->readers.push_back(std::move(record));
  }
}

native_string_ownership::~native_string_ownership() = default;

void native_string_ownership::record_string_encoding(llvm::ArrayRef<string_encoding_result> results) {
  if (!snapshot_) { return; }
  for (const string_encoding_result& result : results) {
    const bool authenticated =
        result.key_schedule == string_key_schedule_kind::blake2s_keyed_auth_v3;
    const bool local_decode = result.mode == string_encoding_mode::inline_stack_decode ||
                              result.mode == string_encoding_mode::ephemeral_slot ||
                              result.strategy_kind == string_strategy_kind::ephemeral_micro_slot;
    // Match the string encoder's sanctioned strong strategies. Generated VM
    // pointer forwarding can legitimately select an authenticated constructor.
    if (!result.applied || !result.has_strong_vm_use || (!local_decode && !authenticated)) {
      continue;
    }
    for (snapshot::definition& definition : snapshot_->definitions) {
      snapshot::identity& identity = snapshot_->identities[definition.symbol];
      if (identity.original_name != result.global_name || definition.kind != definition_kind::plaintext) {
        continue;
      }
      definition.strong_encoding = true;
      definition.authenticated_destination =
          authenticated && (result.mode == string_encoding_mode::global_ctor ||
                            result.mode == string_encoding_mode::lazy_decode);
      if (snapshot_->live_value(definition.symbol) == nullptr && authenticated) {
        identity.erased_by_strong_encoding = true;
      }
    }
  }
}

bool native_string_ownership::emit(llvm::Module& module) {
  if (!snapshot_) { return false; }
  const llvm::Triple triple(module.getTargetTriple());
  // Include generated providers too, but use their explicit binary provenance,
  // never a final-image byte pattern, as the positive non-string classification.
  for (llvm::GlobalVariable& global : module.globals()) {
    if (!global.isDeclarationForLinker() && !is_metadata_global(global) &&
        !snapshot_->identities[snapshot_->identify(global)].has_definition) {
      snapshot_->classify_definition(global);
    }
  }
  for (llvm::GlobalAlias& alias : module.aliases()) {
    if (!alias.isDeclarationForLinker() && !is_metadata_global(alias) &&
        !snapshot_->identities[snapshot_->identify(alias)].has_definition) {
      snapshot_->classify_definition(alias);
    }
  }

  // Private assembler labels are commonly omitted from object symbol tables.
  // Internal linkage retains the same object-local identity without exporting
  // anything, keeping data live, or introducing an archive-extraction edge.
  for (const snapshot::identity& identity : snapshot_->identities) {
    auto* value = llvm::dyn_cast_or_null<llvm::GlobalValue>(static_cast<llvm::Value*>(identity.value));
    if (value != nullptr && !value->isDeclarationForLinker()) {
      if (value->hasPrivateLinkage()) { value->setLinkage(llvm::GlobalValue::InternalLinkage); }
      if (!value->hasName()) {
        value->setName((llvm::Twine("ns_") + llvm::Twine(snapshot_->module_id) + "_" +
                        llvm::Twine(&identity - snapshot_->identities.data())).str());
      }
    }
  }

  llvm::Mangler mangler;
  const auto symbol_record = [&](unsigned index) -> llvm::json::Object {
    llvm::GlobalValue* value = snapshot_->live_value(index);
    if (value == nullptr) {
      llvm::report_fatal_error("native string ownership has no live object symbol");
    }
    llvm::SmallString<128> symbol;
    mangler.getNameWithPrefix(symbol, value, true);
    return llvm::json::Object{{"symbol", symbol.str().str()}, {"local", value->hasLocalLinkage()}};
  };
  struct encoded_entry { std::string key; unsigned kind; llvm::json::Object body; };
  std::vector<encoded_entry> entries;
  for (const snapshot::reader& reader : snapshot_->readers) {
    llvm::GlobalValue* owner = snapshot_->live_value(reader.owner);
    if (owner == nullptr || owner->isDeclarationForLinker()) { continue; }
    llvm::SmallString<128> owner_symbol;
    mangler.getNameWithPrefix(owner_symbol, owner, true);
    llvm::json::Array dependencies;
    for (unsigned dependency : reader.dependencies) {
      if (!snapshot_->omit_erased(dependency)) { dependencies.push_back(symbol_record(dependency)); }
    }
    entries.push_back({owner_symbol.str().str(), 1,
                       llvm::json::Object{{"owner", owner_symbol.str().str()},
                                          {"local", owner->hasLocalLinkage()},
                                          {"dependencies", std::move(dependencies)}}});
  }
  for (const snapshot::definition& definition : snapshot_->definitions) {
    llvm::GlobalValue* value = snapshot_->live_value(definition.symbol);
    if (value == nullptr || value->isDeclarationForLinker()) { continue; }
    definition_kind kind = definition.kind;
    if (definition.kind == definition_kind::plaintext) {
      const auto* global = llvm::dyn_cast<llvm::GlobalVariable>(value);
      const bool local_encoding =
          global != nullptr &&
          support::get_encoded_data_kind(*global) == support::encoded_data_kind::local_string;
      const bool authenticated_destination =
          definition.authenticated_destination && global != nullptr && global->hasLocalLinkage() &&
          !global->isConstant() && global->hasInitializer() &&
          llvm::isa<llvm::ConstantAggregateZero>(global->getInitializer());
      if (definition.strong_encoding && (local_encoding || authenticated_destination)) {
        kind = definition_kind::protected_string;
      } else if (global == nullptr || !is_source_string_candidate(*global)) {
        kind = definition_kind::unknown;
      }
    }
    llvm::json::Array targets;
    bool lost_unproved_target = false;
    for (unsigned target : definition.targets) {
      if (snapshot_->live_value(target) != nullptr) {
        targets.push_back(symbol_record(target));
      } else if (!snapshot_->identities[target].erased_by_strong_encoding) {
        lost_unproved_target = true;
      }
    }
    if (lost_unproved_target) {
      // Ordinary VM remains best-effort. An unowned erased source is not a
      // compile error, nor positive non-string provenance. A strict reader of
      // this provider will instead encounter unknown provenance at final link.
      kind = definition_kind::unknown;
      targets = llvm::json::Array{};
    } else if (kind == definition_kind::forward && targets.empty()) {
      kind = definition_kind::non_string;
    }
    llvm::json::Object body = symbol_record(definition.symbol);
    const std::string key = body.getString("symbol")->str();
    body["kind"] = kind_name(kind);
    body["targets"] = std::move(targets);
    entries.push_back({key, 2, std::move(body)});
  }
  if (entries.empty()) { return false; }
  std::sort(entries.begin(), entries.end(), [](const encoded_entry& lhs, const encoded_entry& rhs) {
    return lhs.kind == rhs.kind ? lhs.key < rhs.key : lhs.kind < rhs.kind;
  });
  std::string payload;
  for (encoded_entry& entry : entries) { append_entry(payload, entry.kind, std::move(entry.body)); }
  if (payload.size() > std::numeric_limits<std::uint32_t>::max() ||
      entries.size() > std::numeric_limits<std::uint32_t>::max()) {
    llvm::report_fatal_error("native string ownership exceeds object record limit");
  }
  std::string bytes = "OBNS";
  append_little_endian(bytes, 1, 2);
  append_little_endian(bytes, 32, 2);
  append_little_endian(bytes, payload.size(), 4);
  append_little_endian(bytes, entries.size(), 4);
  append_little_endian(bytes, snapshot_->module_id, 8);
  append_little_endian(bytes, 0, 4);
  append_little_endian(bytes, 0, 4);
  bytes += payload;

  std::string assembly;
  llvm::raw_string_ostream stream(assembly);
  stream << (triple.isOSBinFormatCOFF() ? "\n.pushsection .obfns,\"diny\"\n"
                                      : "\n.pushsection .obfns,\"\"\n");
  for (std::size_t offset = 0; offset < bytes.size(); offset += 24) {
    stream << ".byte ";
    const std::size_t end = std::min(offset + 24, bytes.size());
    for (std::size_t index = offset; index < end; ++index) {
      if (index != offset) { stream << ','; }
      stream << static_cast<unsigned>(static_cast<unsigned char>(bytes[index]));
    }
    stream << '\n';
  }
  stream << ".popsection\n";
  stream.flush();
  module.appendModuleInlineAsm(assembly);
  module.getOrInsertNamedMetadata("obf.native.ownership.emitted");
  return true;
}
}  // namespace obf
