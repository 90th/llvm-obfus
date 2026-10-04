#include "obf/frontend/config.h"
#include "obf/analysis/function_features.h"
#include "obf/frontend/annotations.h"
#include "obf/policy/policy_engine.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringMap.h"

#include "llvm/ADT/StringSet.h"
#include "llvm/BinaryFormat/Magic.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Object/Archive.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Support/MemoryBuffer.h"

#include "llvm/Config/llvm-config.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/raw_ostream.h"

#include <optional>
#include <memory>

namespace {
llvm::Error reject_dependent_library_metadata(
    const llvm::Module& module, llvm::StringRef source_name) {
  const auto* dependent_libraries = module.getNamedMetadata("llvm.dependent-libraries");
  if (dependent_libraries == nullptr || dependent_libraries->getNumOperands() == 0) {
    return llvm::Error::success();
  }
  const std::string source = source_name.str();
  return llvm::createStringError(
      llvm::inconvertibleErrorCode(),
      "unsupported implicit dependent-library input metadata llvm.dependent-libraries in %s; "
      "pass the library closure explicitly",
      source.c_str());
}


bool references_string(
    const llvm::Constant& root,
    const llvm::StringMap<llvm::SmallVector<const llvm::GlobalValue*, 1>>& definitions,
    llvm::SmallPtrSetImpl<const llvm::Constant*>& visited) {
  if (!visited.insert(&root).second) { return false; }
  if (const auto* data = llvm::dyn_cast<llvm::ConstantDataSequential>(&root)) {
    return data->isCString();
  }
  if (const auto* global = llvm::dyn_cast<llvm::GlobalVariable>(&root)) {
    if (global->hasInitializer()) {
      return references_string(*global->getInitializer(), definitions, visited);
    }
    const auto found = definitions.find(global->getName());
    if (found == definitions.end()) { return false; }
    for (const llvm::GlobalValue* definition : found->second) {
      if (references_string(*definition, definitions, visited)) { return true; }
    }
    return false;
  }
  if (const auto* alias = llvm::dyn_cast<llvm::GlobalAlias>(&root)) {
    return references_string(*alias->getAliasee(), definitions, visited);
  }
  if (llvm::isa<llvm::GlobalValue>(&root) || llvm::isa<llvm::BlockAddress>(&root)) { return false; }
  for (const llvm::Use& operand : root.operands()) {
    if (const auto* constant = llvm::dyn_cast<llvm::Constant>(operand.get())) {
      if (references_string(*constant, definitions, visited)) { return true; }
    }
  }
  return false;
}

llvm::Error validate_thin_string_references(
    llvm::ArrayRef<std::unique_ptr<llvm::Module>> modules,
    const llvm::SmallPtrSetImpl<const llvm::Function*>& readers) {
  if (readers.empty()) { return llvm::Error::success(); }
  llvm::StringMap<llvm::SmallVector<const llvm::GlobalValue*, 1>> definitions;
  for (const auto& module : modules) {
    for (const llvm::GlobalVariable& global : module->globals()) {
      if (!global.hasLocalLinkage() && global.hasInitializer()) {
        definitions[global.getName()].push_back(&global);
      }
    }
    for (const llvm::GlobalAlias& alias : module->aliases()) {
      if (!alias.hasLocalLinkage()) { definitions[alias.getName()].push_back(&alias); }
    }
  }
  for (const llvm::Function* reader : readers) {
    llvm::SmallVector<const llvm::Constant*, 16> pending;
    llvm::SmallPtrSet<const llvm::Constant*, 32> visited;
    const auto enqueue = [&](const llvm::Constant* value) {
      if (llvm::isa<llvm::GlobalVariable, llvm::GlobalAlias,
                    llvm::ConstantExpr, llvm::ConstantAggregate>(value) &&
          visited.insert(value).second) {
        pending.push_back(value);
      }
    };
    for (const llvm::BasicBlock& block : *reader) {
      for (const llvm::Instruction& instruction : block) {
        for (const llvm::Use& operand : instruction.operands()) {
          if (const auto* constant = llvm::dyn_cast<llvm::Constant>(operand.get())) {
            enqueue(constant);
          }
        }
      }
    }
    while (!pending.empty()) {
      const llvm::Constant* value = pending.pop_back_val();
      if (const auto* global = llvm::dyn_cast<llvm::GlobalVariable>(value)) {
        if (global->hasInitializer()) {
          enqueue(global->getInitializer());
          continue;
        }
        llvm::SmallPtrSet<const llvm::Constant*, 32> string_visited;
        if (references_string(*global, definitions, string_visited)) {
          llvm::StringRef owner = reader->getName();
          if (reader->hasFnAttribute("obf.lto.selector")) {
            const auto selector = reader->getFnAttribute("obf.lto.selector").getValueAsString();
            if (!selector.empty()) { owner = selector; }
          }
          return llvm::createStringError(
              llvm::inconvertibleErrorCode(),
              llvm::Twine("strong_vm ThinLTO cannot validate cross-module forwarded string global ") +
                  global->getName() + " referenced by " + owner +
                  ". Keep the string and reader in one translation unit or use Full LTO.");
        }
        continue;
      }
      if (const auto* alias = llvm::dyn_cast<llvm::GlobalAlias>(value)) {
        enqueue(alias->getAliasee());
        continue;
      }
      if (llvm::isa<llvm::GlobalValue>(value) || llvm::isa<llvm::BlockAddress>(value)) { continue; }
      for (const llvm::Use& operand : value->operands()) {
        if (const auto* constant = llvm::dyn_cast<llvm::Constant>(operand.get())) {
          enqueue(constant);
        }
      }
    }
  }
  return llvm::Error::success();
}

llvm::Error collect_lto_definitions(
    llvm::MemoryBufferRef buffer, llvm::StringRef source_name,
    llvm::LLVMContext& context, llvm::StringSet<>& names,
    llvm::StringSet<>& native_names, llvm::StringSet<>& selected_names,
    const obf::obfuscation_config& config,
    llvm::SmallVectorImpl<std::unique_ptr<llvm::Module>>& modules,
    llvm::SmallPtrSetImpl<const llvm::Function*>& thin_string_readers) {
  const llvm::file_magic magic = llvm::identify_magic(buffer.getBuffer());
  if (magic == llvm::file_magic::archive) {
    auto archive = llvm::object::Archive::create(buffer);
    if (!archive) { return archive.takeError(); }
    llvm::Error error = llvm::Error::success();
    for (const auto& child : (*archive)->children(error)) {
      auto member = child.getMemoryBufferRef();
      if (!member) { return member.takeError(); }
      std::string member_source = source_name.str();
      member_source.push_back('(');
      member_source.append(member->getBufferIdentifier().begin(), member->getBufferIdentifier().end());
      member_source.push_back(')');
      if (llvm::Error member_error = collect_lto_definitions(
              *member, member_source, context, names, native_names, selected_names, config,
              modules, thin_string_readers)) {
        return member_error;
      }
    }
    return error;
  }
  if (magic != llvm::file_magic::bitcode) {
    if (magic != llvm::file_magic::elf_relocatable &&
        magic != llvm::file_magic::elf_shared_object &&
        magic != llvm::file_magic::elf_executable) {
      return llvm::Error::success();
    }
    auto object = llvm::object::ObjectFile::createObjectFile(buffer);
    if (!object) { return object.takeError(); }
    const auto collect_symbol = [&](const llvm::object::SymbolRef& symbol) -> llvm::Error {
      auto flags = symbol.getFlags();
      if (!flags) { return flags.takeError(); }
      if ((*flags & llvm::object::SymbolRef::SF_Undefined) != 0 ||
          (*flags & llvm::object::SymbolRef::SF_Global) == 0) {
        return llvm::Error::success();
      }
      auto name = symbol.getName();
      if (!name) { return name.takeError(); }
      native_names.insert(*name);
      return llvm::Error::success();
    };
    for (const auto& symbol : (*object)->symbols()) {
      if (llvm::Error error = collect_symbol(symbol)) { return error; }
    }
    if (const auto* elf = llvm::dyn_cast<llvm::object::ELFObjectFileBase>(object->get())) {
      for (const auto& symbol : elf->getDynamicSymbolIterators()) {
        if (llvm::Error error = collect_symbol(symbol)) { return error; }
      }
    }
    return llvm::Error::success();
  }
  auto lto_info = llvm::getBitcodeLTOInfo(buffer);
  if (!lto_info) { return lto_info.takeError(); }
  auto module = llvm::parseBitcodeFile(buffer, context);
  if (!module) { return module.takeError(); }
  if (llvm::Error error = reject_dependent_library_metadata(**module, source_name)) {
    return error;
  }

  std::optional<obf::obfuscation_config> resolved_config;
  if (config.frontend != obf::frontend_kind::generic) {
    resolved_config.emplace(config);
    for (auto& rule : resolved_config->targets) {
      if (const auto* function = obf::resolve_configured_function(**module, rule.match)) {
        rule.match = function->getName().str();
      }
    }
    for (auto& override : resolved_config->overrides) {
      if (const auto* function = obf::resolve_configured_function(**module, override.name)) {
        override.name = function->getName().str();
      }
    }
  }
  const auto& policy_config = resolved_config.has_value() ? *resolved_config : config;
  const auto annotations = obf::collect_function_annotations(**module);
  llvm::SmallPtrSet<const llvm::Function*, 16> selected_functions;
  for (const llvm::Function& function : **module) {
    if (function.isDeclaration()) { continue; }
    names.insert(function.getName());
    if (function.hasFnAttribute("obf.lto.selector")) {
      names.insert(function.getFnAttribute("obf.lto.selector").getValueAsString());
    }
    const bool has_retained_level = function.hasFnAttribute("obf.lto.level");
    const bool retained =
        has_retained_level && function.getFnAttribute("obf.lto.level").getValueAsString() != "none";
    bool selected = retained;
    bool strong_string = retained &&
        function.getFnAttribute("obf.lto.level").getValueAsString() == "strong_vm";
    strong_string |= function.hasFnAttribute("obf.string.owner.level") &&
        function.getFnAttribute("obf.string.owner.level").getValueAsString() == "strong_vm";
    if (!has_retained_level) {
      const std::string* annotation = obf::find_function_annotation(annotations, function.getName());
      const auto decision = obf::select_policy(
          **module, obf::collect_function_features(function), policy_config,
          annotation == nullptr ? llvm::StringRef{} : llvm::StringRef(*annotation));
      selected = decision.policy.level != obf::protection_level::none;
      strong_string |= decision.policy.level == obf::protection_level::strong_vm;
    }
    if (lto_info->IsThinLTO && strong_string) { thin_string_readers.insert(&function); }
    if (selected) { selected_functions.insert(&function); }
    if (selected && !function.hasLocalLinkage()) {
      selected_names.insert(function.getName());
      if (retained && function.hasFnAttribute("obf.lto.selector")) {
        selected_names.insert(function.getFnAttribute("obf.lto.selector").getValueAsString());
      }
    }
  }
  for (const llvm::GlobalAlias& alias : (*module)->aliases()) {
    const auto* function = llvm::dyn_cast_or_null<llvm::Function>(alias.getAliaseeObject());
    if (function != nullptr && !function->isDeclaration()) {
      names.insert(alias.getName());
      if (!alias.hasLocalLinkage() && selected_functions.contains(function)) {
        selected_names.insert(alias.getName());
      }
    }
  }
  if (config.frontend != obf::frontend_kind::generic) {
    for (const auto& rule : config.targets) {
      if (obf::resolve_configured_function(**module, rule.match) != nullptr) {
        names.insert(rule.match);
      }
    }
    for (const auto& override : config.overrides) {
      if (obf::resolve_configured_function(**module, override.name) != nullptr) {
        names.insert(override.name);
      }
    }
  }
  modules.push_back(std::move(*module));
  return llvm::Error::success();
}

llvm::Error validate_lto_inputs(
    const llvm::cl::list<std::string>& paths, const obf::obfuscation_config& config) {
  llvm::LLVMContext context;
  llvm::StringSet<> names;
  llvm::StringSet<> native_names;
  llvm::StringSet<> selected_names;
  llvm::SmallVector<std::unique_ptr<llvm::Module>, 8> modules;
  llvm::SmallPtrSet<const llvm::Function*, 16> thin_string_readers;
  for (const std::string& path : paths) {
    auto buffer = llvm::MemoryBuffer::getFile(path);
    if (!buffer) {
      return llvm::createStringError(buffer.getError(), "cannot read LTO input %s", path.c_str());
    }
    if (llvm::Error error = collect_lto_definitions(
            (*buffer)->getMemBufferRef(), path, context, names, native_names, selected_names,
            config, modules, thin_string_readers)) {
      return error;
    }
  }
  const auto require_definition = [&](llvm::StringRef name, obf::protection_level level) -> llvm::Error {
    if (level == obf::protection_level::none || name.contains('*') || name.contains('?')) {
      return llvm::Error::success();
    }
    if (native_names.contains(name) && selected_names.contains(name)) {
      return llvm::createStringError(
          llvm::inconvertibleErrorCode(),
          "requested LTO protection target %s has a competing native definition; use bitcode-only definitions",
          name.str().c_str());
    }
    if (names.contains(name)) { return llvm::Error::success(); }
    return llvm::createStringError(
        llvm::inconvertibleErrorCode(), "requested LTO protection target %s has no bitcode definition",
        name.str().c_str());
  };
  for (const auto& rule : config.targets) {
    bool overridden = false;
    for (const auto& override : config.overrides) {
      if (override.name == rule.match) { overridden = true; break; }
    }
    if (!overridden) {
      if (llvm::Error error = require_definition(rule.match, rule.level)) { return error; }
    }
  }
  for (const auto& override : config.overrides) {
    if (llvm::Error error = require_definition(override.name, override.level)) { return error; }
  }
  for (const auto& selected : selected_names) {
    if (llvm::Error error = require_definition(selected.getKey(), obf::protection_level::strong)) {
      return error;
    }
  }
  return validate_thin_string_references(modules, thin_string_readers);
}

}  // namespace

int main(int argc, char** argv) {
  llvm::InitLLVM init_llvm(argc, argv);

  llvm::cl::OptionCategory driver_category("llvm-obfus options");
  llvm::cl::opt<std::string> config_path("config",
                                         llvm::cl::desc("Path to llvm-obfus milestone-zero config"),
                                         llvm::cl::init(""),
                                         llvm::cl::cat(driver_category));
  llvm::cl::opt<std::string> frontend(
      "frontend",
      llvm::cl::desc("Frontend invoking the driver (generic, rust, zig, or tinygo)"),
      llvm::cl::init(""),
      llvm::cl::cat(driver_category));
  llvm::cl::opt<std::string> required_frontend(
      "require-frontend",
      llvm::cl::desc("Require the loaded config to select this frontend"),
      llvm::cl::init(""),
      llvm::cl::cat(driver_category));
  llvm::cl::opt<bool> quiet("quiet",
                            llvm::cl::desc("Suppress successful driver output"),
                            llvm::cl::init(false),
                            llvm::cl::cat(driver_category));
  llvm::cl::opt<bool> query_self_checksum(
      "query-self-checksum",
      llvm::cl::desc("Print whether the resolved config enables self_checksum"),
      llvm::cl::init(false),
      llvm::cl::cat(driver_category));
  llvm::cl::list<std::string> lto_inputs(
      "validate-lto-input", llvm::cl::desc("Validate requested protection across LTO input definitions"),
      llvm::cl::ZeroOrMore, llvm::cl::cat(driver_category));
  llvm::cl::HideUnrelatedOptions(driver_category);
  llvm::cl::ParseCommandLineOptions(argc, argv, "llvm-obfus driver scaffold\n");

  if (!frontend.empty() && frontend != "generic" && frontend != "rust" && frontend != "zig" &&
      frontend != "tinygo") {
    llvm::errs() << "unsupported frontend: " << frontend << '\n';
    return 1;
  }
  if (!required_frontend.empty() && !frontend.empty() && required_frontend != frontend) {
    llvm::errs() << "--require-frontend and --frontend must name the same frontend\n";
    return 1;
  }
  if (!required_frontend.empty() && config_path.empty()) {
    llvm::errs() << "--require-frontend requires --config\n";
    return 1;
  }
  if (!required_frontend.empty() && required_frontend != "generic" && required_frontend != "rust" &&
      required_frontend != "zig" && required_frontend != "tinygo") {
    llvm::errs() << "unsupported required frontend: " << required_frontend << '\n';
    return 1;
  }

  if (!quiet && !query_self_checksum) {
    llvm::outs() << "llvm-obfus driver scaffold\n";
    llvm::outs() << "LLVM version target: " << LLVM_VERSION_STRING << "\n";
  }

  std::optional<obf::obfuscation_config> loaded_config;
  if (!config_path.empty()) {
    llvm::Expected<obf::obfuscation_config> config = obf::load_config_from_file(config_path);
    if (!config) {
      llvm::errs() << llvm::toString(config.takeError()) << '\n';
      return 1;
    }
    const llvm::StringRef expected_frontend =
        !required_frontend.empty() ? llvm::StringRef(required_frontend) : llvm::StringRef(frontend);
    if (!expected_frontend.empty() && obf::to_string(config->frontend) != expected_frontend) {
      llvm::errs() << "config frontend is " << obf::to_string(config->frontend) << "; expected "
                   << expected_frontend << '\n';
      return 1;
    }
    loaded_config.emplace(*config);

    if (!quiet && !query_self_checksum) {
      llvm::outs() << "Loaded config from " << config_path << "\n";
      llvm::outs() << obf::summarize_config(*loaded_config);
    }
  } else if (!quiet && !query_self_checksum) {
    llvm::outs() << "No config provided. Using default milestone-zero policy "
                    "inputs.\n";
  }

  if (!lto_inputs.empty()) {
    const obf::obfuscation_config config = loaded_config.value_or(obf::obfuscation_config{});
    if (llvm::Error error = validate_lto_inputs(lto_inputs, config)) {
      llvm::errs() << llvm::toString(std::move(error)) << '\n';
      return 1;
    }
    return 0;
  }

  if (query_self_checksum) {
    const bool enabled =
        loaded_config.has_value() && loaded_config->self_checksum.enabled;
    llvm::outs() << (enabled ? "enabled\n" : "disabled\n");
    return 0;
  }

  if (!quiet) {
    llvm::outs() << "Initial workflow: build the pass plugin and run policy-aware "
                    "feature reporting or block splitting through opt.\n";
  }
  return 0;
}
