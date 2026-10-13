#include "obf/transforms/string_copy.h"

#include "obf/report/coverage_report.h"
#include "obf/string_copy.h"
#include "obf/support/auth_encoding.h"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <cstdint>
#include <iterator>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace obf {
namespace {

constexpr llvm::StringLiteral annotation_prefix = "obf.string_copy.v1:";
constexpr llvm::StringLiteral source_marker = "obf.string_copy.source";
constexpr llvm::StringLiteral export_ledger = "obf.string_copy.exports";
constexpr llvm::StringLiteral helper_marker = "obf.string_copy.helper";
constexpr std::uint64_t maximum_length = 1024 * 1024;

struct export_record {
  llvm::GlobalVariable* source = nullptr;
  llvm::Function* helper = nullptr;
  llvm::Function* accessor = nullptr;
  std::uint32_t id = 0;
  std::uint64_t length = 0;
};

std::string evidence(const export_record& record, llvm::StringRef reason) {
  return (llvm::Twine("source=") + record.source->getName() + ", accessor=" +
          record.accessor->getName() + ", id=" + llvm::Twine(record.id) + ", " + reason).str();
}

[[noreturn]] void fail(llvm::Module& module, const llvm::Twine& reason,
                       const export_record* record = nullptr,
                       llvm::StringRef code = "binding") {
  const std::string detail =
      (llvm::Twine("code=") + code + ", " +
       (record != nullptr ? evidence(*record, reason.str()) : reason.str())).str();
  record_coverage_event(module, "finalization", "string_copy_export",
                        record != nullptr ? record->accessor->getName() : llvm::StringRef(),
                        record != nullptr ? record->source->getName() : module.getName(),
                        "rejected", detail, 0, "global");
  write_coverage_report(module);
  llvm::report_fatal_error(llvm::Twine("obf-string-copy: ") + detail);
}

llvm::Value* metadata_value(const llvm::MDNode& node, unsigned index) {
  const auto* value = llvm::dyn_cast_or_null<llvm::ValueAsMetadata>(node.getOperand(index).get());
  return value != nullptr ? value->getValue() : nullptr;
}

const llvm::ConstantInt* metadata_integer(const llvm::MDNode& node, unsigned index,
                                          unsigned width) {
  const auto* integer = llvm::dyn_cast_or_null<llvm::ConstantInt>(metadata_value(node, index));
  return integer != nullptr && integer->getBitWidth() == width ? integer : nullptr;
}

export_record read_record(llvm::Module& module, llvm::GlobalVariable& source) {
  const llvm::MDNode* node = source.getMetadata(source_marker);
  if (node == nullptr || node->getNumOperands() != 4) {
    fail(module, "source metadata is missing or malformed");
  }
  export_record record;
  record.source = &source;
  record.helper = llvm::dyn_cast_or_null<llvm::Function>(metadata_value(*node, 0));
  record.accessor = llvm::dyn_cast_or_null<llvm::Function>(metadata_value(*node, 1));
  const auto* id = metadata_integer(*node, 2, 32);
  const auto* length = metadata_integer(*node, 3, 64);
  if (record.helper == nullptr || record.accessor == nullptr || id == nullptr || length == nullptr ||
      record.helper->getParent() != &module || record.accessor->getParent() != &module ||
      length->isZero() || length->getZExtValue() > maximum_length) {
    fail(module, "source metadata has invalid helper, accessor, ID, or length");
  }
  record.id = static_cast<std::uint32_t>(id->getZExtValue());
  record.length = length->getZExtValue();
  return record;
}

llvm::FunctionType* accessor_type(llvm::LLVMContext& context) {
  llvm::Type* pointer = llvm::PointerType::getUnqual(context);
  return llvm::FunctionType::get(llvm::Type::getInt32Ty(context),
                                 {llvm::Type::getInt32Ty(context), pointer,
                                  llvm::Type::getInt64Ty(context), pointer}, false);
}

llvm::FunctionType* helper_type(llvm::LLVMContext& context) {
  llvm::Type* pointer = llvm::PointerType::getUnqual(context);
  return llvm::FunctionType::get(llvm::Type::getInt32Ty(context), {pointer, pointer}, false);
}

llvm::FunctionType* runtime_type(llvm::LLVMContext& context) {
  llvm::Type* pointer = llvm::PointerType::getUnqual(context);
  llvm::Type* integer = llvm::Type::getInt64Ty(context);
  return llvm::FunctionType::get(pointer, {pointer, integer, integer, pointer}, false);
}

bool is_identifier(llvm::StringRef text) {
  const auto letter = [](char value) {
    return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || value == '_';
  };
  if (text.empty() || !letter(text.front())) { return false; }
  for (char value : text.drop_front()) {
    if (!letter(value) && (value < '0' || value > '9')) { return false; }
  }
  return true;
}

bool parse_id(llvm::StringRef text, std::uint32_t& id) {
  while (!text.empty() && (text.back() == 'u' || text.back() == 'U' ||
                          text.back() == 'l' || text.back() == 'L')) {
    text = text.drop_back();
  }
  std::uint64_t value = 0;
  if (text.empty() || text.front() < '0' || text.front() > '9' ||
      text.getAsInteger(0, value) || value > std::numeric_limits<std::uint32_t>::max()) {
    return false;
  }
  id = static_cast<std::uint32_t>(value);
  return true;
}

bool is_annotation_or_used_path(const llvm::User& user,
                                llvm::SmallPtrSetImpl<const llvm::User*>& visited) {
  if (!visited.insert(&user).second) { return true; }
  if (const auto* global = llvm::dyn_cast<llvm::GlobalVariable>(&user)) {
    return global->getName() == "llvm.global.annotations" || global->getName() == "llvm.used" ||
           global->getName() == "llvm.compiler.used";
  }
  if (!llvm::isa<llvm::Constant>(&user) || user.user_empty()) { return false; }
  for (const llvm::User* next : user.users()) {
    if (!is_annotation_or_used_path(*next, visited)) { return false; }
  }
  return true;
}

std::uint64_t source_length(llvm::Module& module, llvm::GlobalVariable& source) {
  const auto* array = llvm::dyn_cast<llvm::ArrayType>(source.getValueType());
  if (!source.hasLocalLinkage() || !source.isConstant() || !source.hasInitializer() ||
      source.isThreadLocal() || source.isExternallyInitialized() || source.hasComdat() ||
      source.getAddressSpace() != 0 || array == nullptr || !array->getElementType()->isIntegerTy(8)) {
    fail(module, llvm::Twine("source '") + source.getName() +
                     "' must be a static const char array without TLS or external storage",
         nullptr, "source_kind");
  }
  const std::uint64_t length = array->getNumElements();
  if (length == 0 || length > maximum_length) {
    fail(module, llvm::Twine("source '") + source.getName() +
                     "' must contain 1 to 1048576 bytes including NUL",
         nullptr, "source_length");
  }
  const auto* bytes = llvm::dyn_cast<llvm::ConstantDataSequential>(source.getInitializer());
  const bool empty = length == 1 && source.getInitializer()->isNullValue();
  if (!empty && (bytes == nullptr || !bytes->isCString() || bytes->getNumElements() != length)) {
    fail(module, llvm::Twine("source '") + source.getName() +
                     "' must have one final NUL, no embedded NUL, and no trailing padding",
         nullptr, "source_bytes");
  }
  llvm::SmallPtrSet<const llvm::User*, 16> visited;
  for (const llvm::User* user : source.users()) {
    if (!is_annotation_or_used_path(*user, visited)) {
      fail(module, llvm::Twine("source '") + source.getName() +
                       "' is shared outside its generated copy accessor",
           nullptr, "source_uses");
    }
  }
  return length;
}

void check_accessor_signature(llvm::Module& module, const llvm::Function& accessor) {
  if (accessor.getFunctionType() != accessor_type(module.getContext()) ||
      accessor.getCallingConv() != llvm::CallingConv::C || !accessor.hasExternalLinkage() ||
      accessor.getVisibility() != llvm::GlobalValue::DefaultVisibility) {
    fail(module, llvm::Twine("accessor '") + accessor.getName() +
                     "' must use OBF_STRING_COPY_DECLARE_V1 and export the C ABI int(uint32_t, char*, size_t, size_t*)",
         nullptr, "accessor_abi");
  }
  if (accessor.hasFnAttribute(llvm::Attribute::NoReturn) ||
      accessor.hasFnAttribute(llvm::Attribute::ReturnsTwice) ||
      accessor.hasFnAttribute(llvm::Attribute::Naked) ||
      accessor.hasFnAttribute(llvm::Attribute::AlwaysInline) ||
      accessor.onlyReadsMemory() || accessor.onlyWritesMemory()) {
    fail(module, llvm::Twine("accessor '") + accessor.getName() +
                     "' has attributes that conflict with the generated copy contract");
  }
  for (unsigned index = 0; index < accessor.arg_size(); ++index) {
    const llvm::AttributeSet attributes = accessor.getAttributes().getParamAttrs(index);
    for (llvm::Attribute attribute : attributes) {
      if (!attribute.isStringAttribute() &&
          (attribute.getKindAsEnum() == llvm::Attribute::ByVal ||
           attribute.getKindAsEnum() == llvm::Attribute::StructRet ||
           attribute.getKindAsEnum() == llvm::Attribute::InAlloca ||
           attribute.getKindAsEnum() == llvm::Attribute::Preallocated ||
           attribute.getKindAsEnum() == llvm::Attribute::InReg ||
           attribute.getKindAsEnum() == llvm::Attribute::SwiftSelf ||
           attribute.getKindAsEnum() == llvm::Attribute::SwiftError ||
           attribute.getKindAsEnum() == llvm::Attribute::ImmArg ||
           ((index == 1 || index == 3) &&
            (attribute.getKindAsEnum() == llvm::Attribute::NonNull ||
             attribute.getKindAsEnum() == llvm::Attribute::Dereferenceable ||
             attribute.getKindAsEnum() == llvm::Attribute::DereferenceableOrNull ||
             attribute.getKindAsEnum() == llvm::Attribute::ReadOnly)))) {
        fail(module, llvm::Twine("accessor '") + accessor.getName() +
                         "' has unsupported ABI parameter attributes");
      }
    }
  }
}

void emit_accessor(llvm::Module& module, llvm::Function& accessor,
                    const std::vector<export_record>& records) {
  llvm::LLVMContext& context = module.getContext();
  llvm::Type* i64 = llvm::Type::getInt64Ty(context);
  llvm::Type* pointer = llvm::PointerType::getUnqual(context);
  auto argument = accessor.arg_begin();
  llvm::Argument* id = &*argument++;
  llvm::Argument* destination = &*argument++;
  llvm::Argument* capacity = &*argument++;
  llvm::Argument* required = &*argument;
  id->setName("id");
  destination->setName("destination");
  capacity->setName("capacity");
  required->setName("required");
  accessor.addFnAttr(llvm::Attribute::NoUnwind);
  accessor.addFnAttr(llvm::Attribute::NoInline);

  auto* entry = llvm::BasicBlock::Create(context, "entry", &accessor);
  auto* select = llvm::BasicBlock::Create(context, "select", &accessor);
  auto* unknown = llvm::BasicBlock::Create(context, "unknown", &accessor);
  auto* invalid = llvm::BasicBlock::Create(context, "invalid", &accessor);
  auto* insufficient = llvm::BasicBlock::Create(context, "insufficient", &accessor);
  auto* null_destination = llvm::BasicBlock::Create(context, "null_destination", &accessor);
  llvm::IRBuilder<> builder(entry);
  auto* null = llvm::ConstantPointerNull::get(llvm::cast<llvm::PointerType>(pointer));
  builder.CreateCondBr(builder.CreateICmpEQ(required, null), invalid, select);
  builder.SetInsertPoint(select);
  auto* selection = builder.CreateSwitch(id, unknown, records.size());
  builder.SetInsertPoint(unknown);
  builder.CreateStore(llvm::ConstantInt::get(i64, 0), required);
  builder.CreateRet(builder.getInt32(OBF_STRING_COPY_UNKNOWN_ID));
  builder.SetInsertPoint(invalid);
  builder.CreateRet(builder.getInt32(OBF_STRING_COPY_INVALID_ARGUMENT));
  builder.SetInsertPoint(insufficient);
  builder.CreateRet(builder.getInt32(OBF_STRING_COPY_NEED_CAPACITY));
  builder.SetInsertPoint(null_destination);
  builder.CreateCondBr(builder.CreateICmpEQ(capacity, llvm::ConstantInt::get(i64, 0)),
                        insufficient, invalid);

  for (const export_record& record : records) {
    auto* known = llvm::BasicBlock::Create(context, "known", &accessor);
    auto* check_capacity = llvm::BasicBlock::Create(context, "check_capacity", &accessor);
    auto* copy = llvm::BasicBlock::Create(context, "copy", &accessor);
    selection->addCase(builder.getInt32(record.id), known);
    auto* length = llvm::ConstantInt::get(i64, record.length);
    builder.SetInsertPoint(known);
    builder.CreateStore(length, required);
    builder.CreateCondBr(builder.CreateICmpEQ(destination, null), null_destination, check_capacity);
    builder.SetInsertPoint(check_capacity);
    builder.CreateCondBr(builder.CreateICmpULT(capacity, length), insufficient, copy);
    builder.SetInsertPoint(copy);
    llvm::Value* status = builder.CreateCall(record.helper, {record.source, destination}, "copied");
    builder.CreateRet(status);
  }
}

llvm::GlobalVariable* private_global(llvm::Module& module, llvm::Value* value,
                                     bool constant, const export_record& record) {
  auto* global = value != nullptr
                     ? llvm::dyn_cast<llvm::GlobalVariable>(value->stripPointerCasts())
                     : nullptr;
  if (global == nullptr || global->getParent() != &module || !global->hasLocalLinkage() ||
      global->getAddressSpace() != 0 || !global->hasInitializer() ||
      global->isConstant() != constant || global->isThreadLocal() ||
      global->isExternallyInitialized()) {
    fail(module, "authentication requires producer-private globals in the source module", &record);
  }
  return global;
}

const llvm::ConstantStruct* structure(llvm::Module& module, const llvm::GlobalVariable& global,
                                      unsigned count, const export_record& record) {
  const auto* value = llvm::dyn_cast<llvm::ConstantStruct>(global.getInitializer());
  if (value == nullptr || value->getNumOperands() != count ||
      value->getType()->isPacked()) {
    fail(module, "authentication bundle has an invalid runtime ABI layout", &record);
  }
  return value;
}

void integer_field(llvm::Module& module, const llvm::ConstantStruct& value, unsigned index,
                    unsigned width, std::uint64_t expected, const export_record& record) {
  const auto* integer = llvm::dyn_cast<llvm::ConstantInt>(value.getOperand(index));
  if (integer == nullptr || integer->getBitWidth() != width || integer->getZExtValue() != expected) {
    fail(module, "authentication bundle has an invalid trusted integer", &record);
  }
}

std::uint64_t integer_value(llvm::Module& module, const llvm::ConstantStruct& value,
                             unsigned index, const export_record& record) {
  const auto* integer = llvm::dyn_cast<llvm::ConstantInt>(value.getOperand(index));
  if (integer == nullptr || integer->getBitWidth() != 64) {
    fail(module, "authentication bundle has an invalid identity or cookie", &record);
  }
  return integer->getZExtValue();
}

void pointer_field(llvm::Module& module, const llvm::ConstantStruct& value, unsigned index,
                    const llvm::GlobalVariable& expected, const export_record& record) {
  llvm::Constant* pointer = value.getOperand(index);
  if (pointer->getType() != llvm::PointerType::getUnqual(module.getContext()) ||
      pointer->stripPointerCasts() != &expected) {
    fail(module, "authentication bundle has an invalid source or payload path", &record);
  }
}

void byte_array(llvm::Module& module, const llvm::Constant& value, std::uint64_t length,
                 const export_record& record) {
  const auto* type = llvm::dyn_cast<llvm::ArrayType>(value.getType());
  if (type == nullptr || !type->getElementType()->isIntegerTy(8) ||
      type->getNumElements() != length) {
    fail(module, "authentication bundle has an invalid byte-array length", &record);
  }
}

void validate_bundle(llvm::Module& module, const export_record& record,
                       llvm::Value* descriptor_pointer, llvm::Value* topology_pointer,
                       std::uint64_t length, std::uint64_t binding) {
  if (length != record.length) { fail(module, "trusted length does not match the source", &record); }
  auto* descriptor = private_global(module, descriptor_pointer, true, record);
  auto* topology = private_global(module, topology_pointer, true, record);
  const auto* desc = structure(module, *descriptor, 20, record);
  const auto* topo = structure(module, *topology, 11, record);
  integer_field(module, *desc, 0, 32, auth::kStringDescriptorVersionV3, record);
  integer_field(module, *desc, 1, 32, auth::kStringAuthFlagTrapOnFailure, record);
  integer_field(module, *desc, 2, 64, length, record);
  integer_field(module, *desc, 6, 64, binding, record);
  if (auth::DeriveStringBindingId(integer_value(module, *desc, 3, record),
                                  integer_value(module, *desc, 4, record),
                                  integer_value(module, *desc, 5, record)) != binding) {
    fail(module, "trusted binding does not match the descriptor identity", &record);
  }
  byte_array(module, *desc->getOperand(14), auth::kStringNonceBytes, record);
  byte_array(module, *desc->getOperand(15), auth::kStringTagBytes, record);
  pointer_field(module, *topo, 0, *descriptor, record);
  auto* destination_ref = private_global(module, desc->getOperand(16), true, record);
  auto* ciphertext_ref = private_global(module, desc->getOperand(17), true, record);
  auto* key_ref = private_global(module, desc->getOperand(18), true, record);
  auto* state_ref = private_global(module, desc->getOperand(19), false, record);
  const auto* destination = structure(module, *destination_ref, 2, record);
  const auto* ciphertext_reference = structure(module, *ciphertext_ref, 2, record);
  const auto* key_reference = structure(module, *key_ref, 2, record);
  const auto* state = structure(module, *state_ref, 3, record);
  auto* ciphertext = private_global(module, ciphertext_reference->getOperand(1), true, record);
  auto* key = private_global(module, key_reference->getOperand(1), true, record);
  private_global(module, record.source, false, record);
  byte_array(module, *record.source->getInitializer(), length, record);
  byte_array(module, *ciphertext->getInitializer(), length, record);
  byte_array(module, *key->getInitializer(), auth::kBuildKeyBytes, record);
  if (!record.source->getInitializer()->isNullValue() || ciphertext == record.source ||
      ciphertext == key || key == record.source || destination_ref == ciphertext_ref ||
      destination_ref == key_ref || ciphertext_ref == key_ref ||
      descriptor == topology || state_ref->getAlign().valueOrOne() < llvm::Align(8)) {
    fail(module, "authentication bundle has an invalid cache, reference, or state path", &record);
  }
  integer_field(module, *destination, 0, 64, integer_value(module, *desc, 7, record), record);
  integer_field(module, *ciphertext_reference, 0, 64, integer_value(module, *desc, 8, record), record);
  integer_field(module, *key_reference, 0, 64, integer_value(module, *desc, 9, record), record);
  integer_field(module, *state, 0, 64, integer_value(module, *desc, 10, record), record);
  integer_value(module, *state, 1, record);
  integer_value(module, *state, 2, record);
  pointer_field(module, *destination, 1, *record.source, record);
  pointer_field(module, *ciphertext_reference, 1, *ciphertext, record);
  pointer_field(module, *key_reference, 1, *key, record);
  pointer_field(module, *topo, 1, *destination_ref, record);
  pointer_field(module, *topo, 2, *record.source, record);
  pointer_field(module, *topo, 4, *ciphertext_ref, record);
  pointer_field(module, *topo, 5, *ciphertext, record);
  pointer_field(module, *topo, 7, *key_ref, record);
  pointer_field(module, *topo, 8, *key, record);
  pointer_field(module, *topo, 10, *state_ref, record);
  integer_field(module, *desc, 11, 64, length, record);
  integer_field(module, *desc, 12, 64, length, record);
  integer_field(module, *desc, 13, 64, auth::kBuildKeyBytes, record);
  integer_field(module, *topo, 3, 64, length, record);
  integer_field(module, *topo, 6, 64, length, record);
  integer_field(module, *topo, 9, 64, auth::kBuildKeyBytes, record);
}

void collect_callees(const llvm::Value& value,
                       llvm::SmallPtrSetImpl<const llvm::Value*>& visited,
                       llvm::SmallVectorImpl<const llvm::Function*>& functions) {
  if (!visited.insert(&value).second) { return; }
  if (const auto* function = llvm::dyn_cast<llvm::Function>(&value)) {
    functions.push_back(function);
    return;
  }
  if (const auto* global = llvm::dyn_cast<llvm::GlobalVariable>(&value)) {
    if (global->isConstant() && global->hasInitializer()) {
      collect_callees(*global->getInitializer(), visited, functions);
    }
    return;
  }
  if (const auto* user = llvm::dyn_cast<llvm::User>(&value)) {
    for (const llvm::Use& operand : user->operands()) {
      collect_callees(*operand.get(), visited, functions);
    }
  }
}

llvm::SmallPtrSet<const llvm::Function*, 32> reachable_functions(const llvm::Function& accessor) {
  llvm::SmallPtrSet<const llvm::Function*, 32> reachable;
  llvm::SmallVector<const llvm::Function*, 16> pending = {&accessor};
  while (!pending.empty()) {
    const llvm::Function* function = pending.pop_back_val();
    if (!reachable.insert(function).second || function->isDeclaration()) { continue; }
    for (const llvm::Instruction& instruction : llvm::instructions(function)) {
      const llvm::Value* target = nullptr;
      if (const auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
        target = call->getCalledOperand();
      } else if (const auto* result = llvm::dyn_cast<llvm::ReturnInst>(&instruction)) {
        target = result->getReturnValue();
      }
      if (target == nullptr) { continue; }
      llvm::SmallPtrSet<const llvm::Value*, 32> visited;
      collect_callees(*target, visited, pending);
    }
  }
  return reachable;
}

bool depends_on(const llvm::Value& value, const llvm::Value& target,
                  llvm::SmallPtrSetImpl<const llvm::Value*>& visited) {
  if (&value == &target) { return true; }
  if (!visited.insert(&value).second) { return false; }
  if (const auto* global = llvm::dyn_cast<llvm::GlobalVariable>(&value)) {
    return global->isConstant() && global->hasInitializer() &&
           depends_on(*global->getInitializer(), target, visited);
  }
  if (llvm::isa<llvm::GlobalValue>(&value)) { return false; }
  if (const auto* user = llvm::dyn_cast<llvm::User>(&value)) {
    for (const llvm::Use& operand : user->operands()) {
      if (depends_on(*operand.get(), target, visited)) { return true; }
    }
  }
  return false;
}

}  // namespace

bool is_string_copy_source(const llvm::GlobalVariable& global) {
  return global.getMetadata(source_marker) != nullptr;
}

bool prepare_string_copy_exports(llvm::Module& module) {
  if (module.getNamedMetadata(export_ledger) != nullptr) { return false; }
  auto* annotations = module.getNamedGlobal("llvm.global.annotations");
  if (annotations == nullptr || !annotations->hasInitializer()) { return false; }
  const auto* entries = llvm::dyn_cast<llvm::ConstantArray>(annotations->getInitializer());
  if (entries == nullptr) { return false; }
  std::map<std::string, std::vector<export_record>> groups;
  llvm::SmallPtrSet<llvm::GlobalVariable*, 16> sources;
  for (const llvm::Use& use : entries->operands()) {
    const auto* entry = llvm::dyn_cast<llvm::ConstantStruct>(use.get());
    if (entry == nullptr || entry->getNumOperands() < 2) { continue; }
    const auto* text_global =
        llvm::dyn_cast<llvm::GlobalVariable>(entry->getOperand(1)->stripPointerCasts());
    const auto* text = text_global != nullptr && text_global->hasInitializer()
                           ? llvm::dyn_cast<llvm::ConstantDataSequential>(text_global->getInitializer())
                           : nullptr;
    if (text == nullptr || !text->isCString()) { continue; }
    llvm::StringRef annotation = text->getAsCString();
    if (!annotation.starts_with("obf.string_copy")) { continue; }
    if (!annotation.consume_front(annotation_prefix)) {
      fail(module, "unsupported string copy annotation. Use OBF_STRING_COPY_SOURCE_V1",
           nullptr, "annotation_version");
    }
    const auto [name, id_text] = annotation.split(':');
    std::uint32_t id = 0;
    if (!is_identifier(name) || !name.ends_with("_v1") || !parse_id(id_text, id)) {
      fail(module, "annotation requires a C accessor name ending _v1 and a uint32_t integer literal ID",
           nullptr, "annotation_syntax");
    }
    auto* source = llvm::dyn_cast<llvm::GlobalVariable>(entry->getOperand(0)->stripPointerCasts());
    if (source == nullptr || !sources.insert(source).second) {
      fail(module, "each string copy annotation must name a separate static const char array",
           nullptr, "source_declaration");
    }
    const std::uint64_t length = source_length(module, *source);
    auto& records = groups[name.str()];
    for (const export_record& record : records) {
      if (record.id == id) {
        fail(module, llvm::Twine("duplicate ID ") + llvm::Twine(id) + " in accessor '" + name + "'",
             nullptr, "duplicate_id");
      }
    }
    records.push_back({source, nullptr, nullptr, id, length});
  }
  if (groups.empty()) { return false; }
  const llvm::Triple triple(module.getTargetTriple());
  if (triple.getArch() != llvm::Triple::x86_64 || !triple.isOSLinux() ||
      !triple.isOSBinFormatELF() || triple.getEnvironment() != llvm::Triple::GNU ||
      module.getDataLayout().getPointerSizeInBits() != 64 ||
      module.getDataLayout().getProgramAddressSpace() != 0) {
    fail(module, "string copy exports require native Linux x86-64 ELF with glibc");
  }
  llvm::LLVMContext& context = module.getContext();
  for (auto& [name, records] : groups) {
    llvm::GlobalValue* existing = module.getNamedValue(name);
    auto* accessor = llvm::dyn_cast_or_null<llvm::Function>(existing);
    if (existing != nullptr && accessor == nullptr) {
      fail(module, llvm::Twine("accessor name '") + name + "' already names a non-function symbol");
    }
    if (accessor != nullptr) {
      check_accessor_signature(module, *accessor);
      if (!accessor->isDeclaration()) {
        fail(module, llvm::Twine("accessor '") + name +
                         "' already has a body. Remove it and use OBF_STRING_COPY_DECLARE_V1",
             nullptr, "accessor_body");
      }
    } else {
      accessor = llvm::Function::Create(accessor_type(context), llvm::GlobalValue::ExternalLinkage,
                                         name, module);
    }
    for (export_record& record : records) {
      record.accessor = accessor;
      const std::string helper_name = (llvm::Twine("__obf_string_copy_auth_") +
                                       record.source->getName()).str();
      if (module.getNamedValue(helper_name) != nullptr) {
        fail(module, "generated authentication helper name already exists", &record);
      }
      record.helper = llvm::Function::Create(helper_type(context), llvm::GlobalValue::ExternalLinkage,
                                              helper_name, module);
      record.helper->setDSOLocal(true);
      record.helper->addFnAttr(llvm::Attribute::NoUnwind);
      record.helper->addFnAttr(llvm::Attribute::NoInline);
      auto* metadata = llvm::MDNode::get(context,
          {llvm::ValueAsMetadata::get(record.helper), llvm::ValueAsMetadata::get(accessor),
           llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), record.id)),
           llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), record.length))});
      record.source->setMetadata(source_marker, metadata);
      record.source->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::None);
      record.helper->setMetadata(helper_marker, llvm::MDNode::get(context,
          {llvm::ValueAsMetadata::get(record.source)}));
      record_coverage_role(*record.helper, accessor->getName(), "string_decoder",
                            {"authenticated_string_decode"});
      module.getOrInsertNamedMetadata(export_ledger)->addOperand(llvm::MDNode::get(context,
          {llvm::ValueAsMetadata::get(record.source)}));
      record_coverage_event(module, "emission", "string_copy_export", accessor->getName(),
                            record.source->getName(), "generated",
                            evidence(record, "accessor awaits authenticated source binding"), 1, "global");
    }
    emit_accessor(module, *accessor, records);
  }
  llvm::removeFromUsedLists(module, [&](llvm::Constant* value) {
    const auto* global = llvm::dyn_cast<llvm::GlobalVariable>(value->stripPointerCasts());
    return global != nullptr && sources.contains(const_cast<llvm::GlobalVariable*>(global));
  });
  for (llvm::GlobalVariable* source : sources) { source->removeDeadConstantUsers(); }
  return true;
}

void bind_string_copy_authentication(llvm::GlobalVariable& source,
                                     llvm::Constant* descriptor,
                                     llvm::Constant* topology,
                                     std::uint64_t length,
                                     std::uint64_t binding) {
  llvm::Module& module = *source.getParent();
  const export_record record = read_record(module, source);
  if (record.helper->getFunctionType() != helper_type(module.getContext()) ||
      !record.helper->isDeclaration()) {
    fail(module, "authentication helper is already bound or has an invalid signature", &record);
  }
  validate_bundle(module, record, descriptor, topology, length, binding);
  llvm::GlobalValue* runtime_symbol = module.getNamedValue(auth::kRuntimeStringDecodeSymbolV3);
  auto* runtime = llvm::dyn_cast_or_null<llvm::Function>(runtime_symbol);
  if (runtime_symbol != nullptr &&
      (runtime == nullptr || runtime->getFunctionType() != runtime_type(module.getContext()) ||
       runtime->getCallingConv() != llvm::CallingConv::C || !runtime->isDeclaration())) {
    fail(module, "V3 runtime decoder has an invalid declaration", &record);
  }
  auto callee = module.getOrInsertFunction(auth::kRuntimeStringDecodeSymbolV3,
                                           runtime_type(module.getContext()));
  record.helper->setLinkage(llvm::GlobalValue::InternalLinkage);
  record.helper->setDSOLocal(true);
  record.helper->setVisibility(llvm::GlobalValue::DefaultVisibility);
  auto* entry = llvm::BasicBlock::Create(module.getContext(), "entry", record.helper);
  llvm::IRBuilder<> builder(entry);
  auto* decoded = builder.CreateCall(callee,
      {descriptor, builder.getInt64(length), builder.getInt64(binding), topology});
  builder.CreateMemCpy(record.helper->getArg(1), llvm::MaybeAlign(1), decoded,
                       llvm::MaybeAlign(1), builder.getInt64(length));
  builder.CreateRet(builder.getInt32(OBF_STRING_COPY_OK));
  record_coverage_role(*record.helper, record.accessor->getName(), "string_decoder",
                        {"authenticated_string_decode"});
  record_coverage_event(module, "emission", "string_copy_export", record.accessor->getName(),
                        source.getName(), "bound",
                        evidence(record, "private V3 authentication bound before every successful copy"),
                        1, "global");
}

void validate_string_copy_exports(llvm::Module& module) {
  llvm::NamedMDNode* ledger = module.getNamedMetadata(export_ledger);
  llvm::SmallPtrSet<llvm::GlobalVariable*, 16> sources;
  const llvm::Function* cached_accessor = nullptr;
  llvm::SmallPtrSet<const llvm::Function*, 32> reachable;
  if (ledger != nullptr) {
    for (const llvm::MDNode* entry : ledger->operands()) {
      auto* source = entry->getNumOperands() == 1
                         ? llvm::dyn_cast_or_null<llvm::GlobalVariable>(metadata_value(*entry, 0))
                         : nullptr;
      if (source == nullptr || source->getParent() != &module || !sources.insert(source).second) {
        fail(module, "export ledger has a missing, foreign, or duplicate source");
      }
      const export_record record = read_record(module, *source);
      check_accessor_signature(module, *record.accessor);
      if (record.accessor->isDeclaration() || record.helper->isDeclaration() ||
          !record.accessor->hasFnAttribute(llvm::Attribute::NoInline) ||
          !record.accessor->hasFnAttribute(llvm::Attribute::NoUnwind) ||
          !record.helper->hasInternalLinkage() || !record.helper->isDSOLocal() ||
          record.helper->getCallingConv() != llvm::CallingConv::C ||
          record.helper->getFunctionType() != helper_type(module.getContext()) ||
          !record.helper->hasFnAttribute(llvm::Attribute::NoUnwind) ||
          !record.helper->hasFnAttribute(llvm::Attribute::NoInline) || record.helper->size() != 1) {
        fail(module, "export has an unbound or invalid private authentication helper", &record);
      }
      const llvm::MDNode* helper_metadata = record.helper->getMetadata(helper_marker);
      if (helper_metadata == nullptr || helper_metadata->getNumOperands() != 1 ||
          metadata_value(*helper_metadata, 0) != source) {
        fail(module, "authentication helper does not belong to this source", &record);
      }
      const llvm::BasicBlock& block = record.helper->getEntryBlock();
      const auto* call = block.size() == 3 ? llvm::dyn_cast<llvm::CallInst>(&block.front()) : nullptr;
      const auto* copy = block.size() == 3
                             ? llvm::dyn_cast<llvm::MemCpyInst>(&*std::next(block.begin()))
                             : nullptr;
      const auto* result = llvm::dyn_cast<llvm::ReturnInst>(block.getTerminator());
      const auto* status = result != nullptr
                               ? llvm::dyn_cast_or_null<llvm::ConstantInt>(result->getReturnValue())
                               : nullptr;
      const llvm::Function* runtime = call != nullptr ? call->getCalledFunction() : nullptr;
      const auto runtime_symbol = llvm::StringRef(auth::kRuntimeStringDecodeSymbolV3.data(),
                                                   auth::kRuntimeStringDecodeSymbolV3.size());
      if (call == nullptr || copy == nullptr || status == nullptr || status->getBitWidth() != 32 ||
          status->getZExtValue() != OBF_STRING_COPY_OK ||
          runtime == nullptr || runtime->getName() != runtime_symbol ||
          runtime->getFunctionType() != runtime_type(module.getContext()) ||
          runtime->getCallingConv() != llvm::CallingConv::C || !runtime->isDeclaration() ||
          call->getCallingConv() != llvm::CallingConv::C || call->arg_size() != 4 ||
          copy->getRawSource() != call || copy->getRawDest() != record.helper->getArg(1) ||
          copy->isVolatile() || !record.helper->getArg(0)->use_empty()) {
        fail(module, "private helper must authenticate, copy the decoder result, then return OK", &record);
      }
      const auto* length = llvm::dyn_cast<llvm::ConstantInt>(call->getArgOperand(1));
      const auto* binding = llvm::dyn_cast<llvm::ConstantInt>(call->getArgOperand(2));
      if (length == nullptr || binding == nullptr || length->getBitWidth() != 64 ||
          binding->getBitWidth() != 64) {
        fail(module, "V3 runtime call must use trusted constant length and binding", &record);
      }
      const auto* copy_length = llvm::dyn_cast<llvm::ConstantInt>(copy->getLength());
      if (copy_length == nullptr || copy_length->getBitWidth() != 64 ||
          copy_length->getZExtValue() != record.length) {
        fail(module, "private helper must copy the complete source including NUL", &record);
      }
      validate_bundle(module, record, call->getArgOperand(0), call->getArgOperand(3),
                        length->getZExtValue(), binding->getZExtValue());
      if (cached_accessor != record.accessor) {
        reachable = reachable_functions(*record.accessor);
        cached_accessor = record.accessor;
      }
      bool copied = false;
      for (const llvm::Function* function : reachable) {
        if (function->isDeclaration()) { continue; }
        for (const llvm::Instruction& instruction : llvm::instructions(function)) {
          const auto* path = llvm::dyn_cast<llvm::CallBase>(&instruction);
          if (path == nullptr) { continue; }
          llvm::SmallVector<const llvm::Function*, 4> callees;
          llvm::SmallPtrSet<const llvm::Value*, 32> callee_values;
          collect_callees(*path->getCalledOperand(), callee_values, callees);
          bool calls_helper = false;
          for (const llvm::Function* callee : callees) { calls_helper |= callee == record.helper; }
          if (!calls_helper) { continue; }
          llvm::SmallPtrSet<const llvm::Value*, 32> visited;
          if (path->arg_size() != 2 ||
              path->getFunctionType() != helper_type(module.getContext()) ||
              path->getCallingConv() != llvm::CallingConv::C ||
              !depends_on(*path->getArgOperand(0), *source, visited)) {
            fail(module, "copy path lost its original source dependency", &record);
          }
          copied = true;
        }
      }
      if (!copied) { fail(module, "accessor has no authenticated fixed-length copy path", &record); }
      record_coverage_event(module, "finalization", "string_copy_export", record.accessor->getName(),
                            source->getName(), "validated",
                            evidence(record, "live V3 call, private payload binding, and copy path validated"),
                            1, "global");
    }
  }
  for (llvm::GlobalVariable& global : module.globals()) {
    if (is_string_copy_source(global) && !sources.contains(&global)) {
      fail(module, "declared source is absent from the export ledger");
    }
  }
  for (llvm::Function& function : module) {
    if (function.getMetadata(helper_marker) == nullptr) { continue; }
    const llvm::MDNode* marker = function.getMetadata(helper_marker);
    const auto* source = marker->getNumOperands() == 1
                             ? llvm::dyn_cast_or_null<llvm::GlobalVariable>(metadata_value(*marker, 0))
                             : nullptr;
    if (source == nullptr || !sources.contains(const_cast<llvm::GlobalVariable*>(source)) ||
        function.isDeclaration()) {
      fail(module, "unbound or unregistered authentication placeholder remains");
    }
  }
}

}  // namespace obf
