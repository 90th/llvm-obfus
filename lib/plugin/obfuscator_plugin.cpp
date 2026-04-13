#include "obf/frontend/annotations.h"
#include "obf/frontend/config.h"
#include "obf/analysis/function_features.h"
#include "obf/report/function_report.h"
#include "obf/transforms/block_split.h"
#include "obf/transforms/bogus_control_flow.h"
#include "obf/transforms/constant_encoding.h"
#include "obf/transforms/control_flattening.h"
#include "obf/transforms/instruction_substitution.h"
#include "obf/transforms/mba.h"
#include "obf/transforms/opaque_gep.h"
#include "obf/transforms/opaque_predicates.h"
#include "obf/transforms/string_encoding.h"
#include "obf/vm/candidate_analysis.h"
#include "obf/vm/virtualize.h"

#include "llvm/ADT/Hashing.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>

namespace obf {

namespace {

/// Returns true for levels that use the strong-classical transform tuning.
bool has_strong_classical(protection_level level) {
  return level == protection_level::strong ||
         level == protection_level::strong_vm;
}

llvm::cl::opt<std::string> obf_config_path(
    "obf-config",
    llvm::cl::desc("Path to llvm-obfus milestone-zero YAML config"),
    llvm::cl::init(""));

struct function_pipeline_state {
  llvm::Function *function = nullptr;
  function_report_entry report;
};

struct virtualized_call_site {
  llvm::CallBase *call = nullptr;
  std::uint64_t hidden_token = 0;
};

struct virtualized_function_binding {
  llvm::Function *interface_function = nullptr;
  llvm::Function *implementation_function = nullptr;
  const function_pipeline_state *state = nullptr;
  llvm::SmallVector<virtualized_call_site, 8> call_sites;
  std::uint64_t wrapper_token = 0;
};

using virtualized_function_map =
    llvm::StringMap<virtualized_function_binding>;

obfuscation_config load_active_config() {
  if (obf_config_path.empty()) {
    return {};
  }

  llvm::Expected<obfuscation_config> config =
      load_config_from_file(obf_config_path);
  if (!config) {
    const std::string error_message = llvm::toString(config.takeError());
    llvm::report_fatal_error(llvm::StringRef(error_message));
  }

  return *config;
}

llvm::SmallVector<function_pipeline_state, 32>
build_pipeline_state(llvm::Module &module, const obfuscation_config &config) {
  const function_annotation_map annotations = collect_function_annotations(module);

  llvm::SmallVector<function_pipeline_state, 32> states;
  states.reserve(module.size());

  for (llvm::Function &function : module) {
    function_report_entry report;
    report.features = collect_function_features(function);

    if (const std::string *annotation =
            find_function_annotation(annotations, function.getName())) {
      report.annotation = *annotation;
    }

    report.decision =
        select_policy(module, report.features, config, report.annotation);
    states.push_back({.function = &function, .report = std::move(report)});
  }

  return states;
}

template <typename Predicate>
llvm::StringMap<std::uint64_t>
build_function_seed_map(const llvm::SmallVectorImpl<function_pipeline_state> &states,
                        Predicate predicate) {
  llvm::StringMap<std::uint64_t> seeds;
  for (const function_pipeline_state &state : states) {
    if (state.function == nullptr || state.function->isDeclaration()) {
      continue;
    }

    if (!predicate(state.report.decision.policy)) {
      continue;
    }

    seeds[state.function->getName()] = state.report.decision.seed;
  }

  return seeds;
}

block_split_options build_block_split_options(const obfuscation_config &config,
                                              const policy_decision &decision) {
  block_split_options options;
  options.max_splits_per_function =
      config.block_split.max_splits_per_function;
  options.min_instructions_per_block =
      config.block_split.min_instructions_per_block;

  if (decision.policy.level == protection_level::light) {
    options.max_splits_per_function =
        std::min<std::size_t>(options.max_splits_per_function, 1);
  }

  return options;
}

string_encoding_options build_string_encoding_options(const obfuscation_config &config) {
  return {.min_string_length = config.string_encoding.min_string_length,
          .max_strings_per_module = config.string_encoding.max_strings_per_module,
          .ctor_priority = 0,
          .prefer_lazy_decode = config.string_encoding.prefer_lazy_decode,
          .allow_ctor_fallback = config.string_encoding.allow_ctor_fallback};
}

constant_encoding_options
build_constant_encoding_options(const obfuscation_config &config,
                                const policy_decision &decision) {
  constant_encoding_options options;
  options.max_constants_per_function =
      config.constant_encoding.max_constants_per_function;
  options.min_bit_width = config.constant_encoding.min_bit_width;

  if (decision.policy.level == protection_level::light) {
    options.max_constants_per_function =
        std::min<std::size_t>(options.max_constants_per_function, 2);
  }

  options.mba_depth = config.mba.depth;
  return options;
}

control_flattening_options
build_control_flattening_options(const obfuscation_config &,
                                 const policy_decision &decision) {
  control_flattening_options options;
  if (has_strong_classical(decision.policy.level)) {
    options.max_blocks = 20;
    options.max_instructions = 192;
  }

  return options;
}

instruction_substitution_options
build_instruction_substitution_options(const obfuscation_config &config,
                                       const policy_decision &decision) {
  instruction_substitution_options options;
  if (has_strong_classical(decision.policy.level)) {
    options.max_substitutions_per_function = 6;
  } else {
    options.max_substitutions_per_function = 2;
  }

  options.mba_depth = config.mba.depth;
  return options;
}

opaque_gep_options build_opaque_gep_options(const obfuscation_config &config,
                                            const policy_decision &) {
  opaque_gep_options options;
  options.mba_depth = config.mba.depth;
  return options;
}

bogus_control_flow_options
build_bogus_control_flow_options(const obfuscation_config &,
                                 const policy_decision &decision) {
  bogus_control_flow_options options;
  if (has_strong_classical(decision.policy.level)) {
    options.max_insertions_per_function = 2;
  }

  return options;
}

opaque_predicate_options
build_opaque_predicate_options(const obfuscation_config &,
                               const policy_decision &decision) {
  opaque_predicate_options options;
  if (has_strong_classical(decision.policy.level)) {
    options.max_insertions_per_function = 2;
  }

  return options;
}

transform_report_entry make_transform_report(llvm::StringRef pass,
                                             llvm::StringRef target_kind,
                                             llvm::StringRef target_name,
                                             bool applied, llvm::StringRef detail,
                                             std::size_t count) {
  return {.pass = pass.str(),
          .target_kind = target_kind.str(),
          .target_name = target_name.str(),
          .status = applied ? "applied" : "skipped",
          .detail = detail.str(),
          .count = count};
}

llvm::SmallVector<transform_report_entry, 64>
build_transform_reports(llvm::Module &module,
                        const llvm::SmallVectorImpl<function_pipeline_state> &states,
                        const obfuscation_config &config) {
  llvm::SmallVector<transform_report_entry, 64> reports;
  llvm::StringSet<> virtualized_functions;

  for (const function_pipeline_state &state : states) {
    if (state.function == nullptr || !state.report.decision.policy.allow_vm) {
      continue;
    }

    if (vm::analyze_candidate(*state.function).eligible) {
      virtualized_functions.insert(state.function->getName());
    }
  }

  for (const function_pipeline_state &state : states) {
    const llvm::Function *function = state.function;
    if (function == nullptr) {
      continue;
    }

    const bool suppressed_by_vm =
        virtualized_functions.contains(function->getName()) &&
        state.report.decision.policy.level != protection_level::strong_vm;
    const bool deferred_to_vm_hardening =
        virtualized_functions.contains(function->getName()) &&
        state.report.decision.policy.level == protection_level::strong_vm;

    const vm::candidate_result vm_result = vm::analyze_candidate(*function);
    if (!state.report.decision.policy.allow_vm) {
      reports.push_back(make_transform_report(
          "vm", "function", function->getName(), false,
          function->isDeclaration() ? "declaration" : "policy disallows vm", 0));
    } else {
      reports.push_back(make_transform_report(
          "vm", "function", function->getName(), vm_result.eligible,
          vm_result.detail, vm_result.eligible ? vm_result.instruction_count : 0));
    }

    if (suppressed_by_vm) {
      reports.push_back(make_transform_report("block_split", "function",
                                              function->getName(), false,
                                              "suppressed after vm", 0));
    } else if (!state.report.decision.policy.allow_split) {
      reports.push_back(make_transform_report(
          "block_split", "function", function->getName(), false,
          function->isDeclaration() ? "declaration" : "policy disallows split",
          0));
    } else {
      const block_split_options options =
          build_block_split_options(config, state.report.decision);
      const block_split_result result =
          analyze_block_split(*function, options, state.report.decision.seed);
      reports.push_back(make_transform_report("block_split", "function",
                                              function->getName(),
                                              result.split_count > 0,
                                              result.detail, result.split_count));
    }

    if (suppressed_by_vm) {
      reports.push_back(make_transform_report("constant_encoding", "function",
                                              function->getName(), false,
                                              "suppressed after vm", 0));
    } else if (!state.report.decision.policy.allow_constant_encoding) {
      reports.push_back(make_transform_report(
          "constant_encoding", "function", function->getName(), false,
          function->isDeclaration() ? "declaration"
                                    : "policy disallows constant encoding",
          0));
    } else {
      const constant_encoding_options options =
          build_constant_encoding_options(config, state.report.decision);
      const constant_encoding_result result =
          analyze_constant_encoding(*function, options, state.report.decision.seed);
      reports.push_back(make_transform_report(
          "constant_encoding", "function", function->getName(),
          result.encoded_count > 0, result.detail, result.encoded_count));
    }

    if (suppressed_by_vm) {
      reports.push_back(make_transform_report(
          "instruction_substitution", "function", function->getName(), false,
          "suppressed after vm", 0));
    } else if (deferred_to_vm_hardening) {
      reports.push_back(make_transform_report(
          "instruction_substitution", "function", function->getName(), false,
          "deferred to vm hardening", 0));
    } else if (!state.report.decision.policy.allow_instruction_substitution) {
      reports.push_back(make_transform_report(
          "instruction_substitution", "function", function->getName(), false,
          function->isDeclaration() ? "declaration"
                                    : "policy disallows instruction substitution",
          0));
    } else {
      const instruction_substitution_options options =
          build_instruction_substitution_options(config, state.report.decision);
      const instruction_substitution_result result =
          analyze_instruction_substitution(*function, options);
      reports.push_back(make_transform_report(
          "instruction_substitution", "function", function->getName(),
          result.substitution_count > 0, result.detail,
          result.substitution_count));
    }

    if (suppressed_by_vm) {
      reports.push_back(make_transform_report("control_flattening", "function",
                                              function->getName(), false,
                                              "suppressed after vm", 0));
    } else if (deferred_to_vm_hardening) {
      reports.push_back(make_transform_report("control_flattening", "function",
                                              function->getName(), false,
                                              "deferred to vm hardening", 0));
    } else if (!state.report.decision.policy.allow_flattening) {
      reports.push_back(make_transform_report(
          "control_flattening", "function", function->getName(), false,
          function->isDeclaration() ? "declaration"
                                    : "policy disallows flattening",
          0));
    } else {
      const control_flattening_options options =
          build_control_flattening_options(config, state.report.decision);
      const control_flattening_result result =
          analyze_control_flattening(*function, options);
      reports.push_back(make_transform_report(
          "control_flattening", "function", function->getName(),
          result.flattened, result.detail, result.state_count));
    }

    if (suppressed_by_vm) {
      reports.push_back(make_transform_report("opaque_predicates", "function",
                                              function->getName(), false,
                                              "suppressed after vm", 0));
    } else if (!state.report.decision.policy.allow_opaque_predicates) {
      reports.push_back(make_transform_report(
          "opaque_predicates", "function", function->getName(), false,
          function->isDeclaration() ? "declaration"
                                    : "policy disallows opaque predicates",
          0));
    } else {
      const opaque_predicate_options options =
          build_opaque_predicate_options(config, state.report.decision);
      const opaque_predicate_result result =
          analyze_opaque_predicates(*function, options);
      reports.push_back(make_transform_report(
          "opaque_predicates", "function", function->getName(),
          result.insertion_count > 0, result.detail, result.insertion_count));
    }

    if (suppressed_by_vm) {
      reports.push_back(make_transform_report("bogus_control_flow", "function",
                                              function->getName(), false,
                                              "suppressed after vm", 0));
    } else if (!state.report.decision.policy.allow_bogus_control_flow) {
      reports.push_back(make_transform_report(
          "bogus_control_flow", "function", function->getName(), false,
          function->isDeclaration() ? "declaration"
                                    : "policy disallows bogus control flow",
          0));
    } else {
      const bogus_control_flow_options options =
          build_bogus_control_flow_options(config, state.report.decision);
      const bogus_control_flow_result result =
          analyze_bogus_control_flow(*function, options);
      reports.push_back(make_transform_report(
          "bogus_control_flow", "function", function->getName(),
          result.insertion_count > 0, result.detail, result.insertion_count));
    }

  }

  const llvm::StringMap<std::uint64_t> string_function_seeds =
      build_function_seed_map(states, [](const function_policy &policy) {
        return policy.allow_string_encoding;
      });
  const string_encoding_options string_options = build_string_encoding_options(config);
  const std::vector<string_encoding_result> string_results = analyze_string_encoding(
      module,
      [&](llvm::StringRef function_name) -> std::optional<std::uint64_t> {
        const auto iterator = string_function_seeds.find(function_name);
        if (iterator == string_function_seeds.end()) {
          return std::nullopt;
        }

        return iterator->second;
      },
      string_options, config.seed);

  for (const string_encoding_result &result : string_results) {
    const std::string detail =
        result.applied ? (to_string(result.mode) + ": " + result.detail)
                       : result.detail;
    const std::size_t count =
        (result.mode == string_encoding_mode::lazy_decode ||
         result.mode == string_encoding_mode::inline_stack_decode)
            ? result.rewritten_use_count
            : (result.applied ? 1U : 0U);
    transform_report_entry entry = make_transform_report(
        "string_encoding", "global", result.global_name, result.applied, detail,
        count);
    entry.has_strategy_payload = true;
    entry.strategy_kind = to_string(result.strategy_kind);
    entry.helper_shape = to_string(result.helper_shape);
    entry.key_schedule = to_string(result.key_schedule);
    entry.inline_eligible = result.inline_eligible;
    entry.inline_detail = result.inline_detail;
    entry.fallback_reason = result.fallback_reason;
    entry.merge_group = result.merge_group;
    entry.descriptor_index = result.descriptor_index;
    entry.protected_use_count = result.protected_use_count;
    entry.unprotected_use_count = result.unprotected_use_count;
    entry.use_kinds = result.use_kinds;
    reports.push_back(std::move(entry));
  }

  return reports;
}

void verify_changed_module(llvm::Module &module) {
  std::string error_text;
  llvm::raw_string_ostream stream(error_text);
  if (llvm::verifyModule(module, &stream)) {
    stream.flush();
    llvm::report_fatal_error(llvm::StringRef(error_text));
  }
}

bool should_skip_function(const function_pipeline_state &state,
                          const llvm::StringSet<> *skip_functions) {
  if (state.function == nullptr || state.function->isDeclaration()) {
    return true;
  }

  return skip_functions != nullptr &&
         skip_functions->contains(state.function->getName());
}

bool apply_block_split_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions = nullptr) {
  bool changed = false;

  for (const function_pipeline_state &state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_split) {
      continue;
    }

    const block_split_options options =
        build_block_split_options(config, state.report.decision);
    changed |= run_block_split(*state.function, options,
                               state.report.decision.seed)
                   .split_count > 0;
  }

  return changed;
}

std::uint64_t mix_vm_handshake_seed(std::uint64_t seed, std::uint64_t salt) {
  seed ^= salt + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
  return seed;
}

std::uint64_t derive_vm_hidden_token(llvm::StringRef callee_name,
                                     llvm::StringRef caller_name,
                                     std::uint64_t ordinal) {
  std::uint64_t seed =
      static_cast<std::uint64_t>(llvm::hash_value(callee_name));
  seed = mix_vm_handshake_seed(
      seed, static_cast<std::uint64_t>(llvm::hash_value(caller_name)));
  seed = mix_vm_handshake_seed(seed, ordinal + 1);
  return seed == 0 ? 0xa55aa55aa55aa55aULL : seed;
}

std::uint64_t derive_vm_wrapper_token(llvm::StringRef function_name) {
  return derive_vm_hidden_token(function_name, function_name, 0x51f15eedULL);
}

llvm::Value *build_hidden_token_value(llvm::IRBuilder<> &builder,
                                      llvm::Function &owner,
                                      llvm::StringRef prefix,
                                      std::uint64_t token,
                                      std::uint32_t mba_depth,
                                      std::uint64_t salt) {
  mba::builder_context context =
      mba::get_or_create_builder_context(owner, prefix, token ^ salt);
  context.depth = mba_depth;
  return mba::create_opaque_integer(builder, builder.getInt64Ty(), context,
                                    llvm::APInt(64, token), salt,
                                    (prefix + ".token").str());
}

llvm::Function *clone_vm_implementation(llvm::Function &interface_function) {
  llvm::Module *module = interface_function.getParent();
  if (module == nullptr) {
    return nullptr;
  }

  llvm::SmallVector<llvm::Type *, 8> parameter_types;
  parameter_types.reserve(interface_function.arg_size() + 1);
  for (llvm::Argument &argument : interface_function.args()) {
    parameter_types.push_back(argument.getType());
  }
  parameter_types.push_back(llvm::Type::getInt64Ty(module->getContext()));

  auto *implementation_type = llvm::FunctionType::get(
      interface_function.getReturnType(), parameter_types, /*isVarArg=*/false);
  auto *implementation_function = llvm::Function::Create(
      implementation_type, llvm::GlobalValue::ExternalLinkage,
      ("__obf_vm_impl_" + interface_function.getName()).str(), module);
  implementation_function->setCallingConv(interface_function.getCallingConv());
  implementation_function->setAttributes(interface_function.getAttributes());
  implementation_function->setDSOLocal(true);

  llvm::ValueToValueMapTy value_map;
  auto implementation_arg = implementation_function->arg_begin();
  for (llvm::Argument &argument : interface_function.args()) {
    implementation_arg->setName(argument.getName());
    value_map[&argument] = &*implementation_arg++;
  }
  implementation_arg->setName("obf.hidden_token");

  llvm::SmallVector<llvm::ReturnInst *, 8> returns;
  llvm::CloneFunctionInto(implementation_function, &interface_function, value_map,
                          llvm::CloneFunctionChangeType::LocalChangesOnly,
                          returns);
  return implementation_function;
}

void rewrite_vm_interface_wrapper(llvm::Function &interface_function,
                                  llvm::Function &implementation_function,
                                  std::uint64_t wrapper_token,
                                  std::uint32_t mba_depth) {
  interface_function.deleteBody();

  llvm::BasicBlock *entry = llvm::BasicBlock::Create(
      interface_function.getContext(), "entry.obf.vm.wrapper",
      &interface_function);
  llvm::IRBuilder<> builder(entry);
  llvm::Value *hidden_token = build_hidden_token_value(
      builder, interface_function,
      (interface_function.getName() + ".obf.wrapper").str(), wrapper_token,
      mba_depth, 0x6000ULL);

  llvm::SmallVector<llvm::Value *, 8> arguments;
  arguments.reserve(interface_function.arg_size() + 1);
  for (llvm::Argument &argument : interface_function.args()) {
    arguments.push_back(&argument);
  }
  arguments.push_back(hidden_token);

  auto *call = builder.CreateCall(implementation_function.getFunctionType(),
                                  &implementation_function, arguments,
                                  interface_function.getReturnType()->isVoidTy()
                                      ? ""
                                      : (interface_function.getName() +
                                         ".obf.wrapper.call")
                                            .str());
  call->setCallingConv(interface_function.getCallingConv());
  call->setAttributes(implementation_function.getAttributes());
  if (interface_function.getReturnType()->isVoidTy()) {
    builder.CreateRetVoid();
  } else {
    builder.CreateRet(call);
  }
}

virtualized_function_binding
prepare_virtualized_function_binding(const function_pipeline_state &state,
                                     std::uint32_t mba_depth) {
  virtualized_function_binding binding;
  llvm::Function *interface_function = state.function;
  if (interface_function == nullptr || interface_function->isDeclaration()) {
    return binding;
  }

  llvm::SmallVector<llvm::CallBase *, 16> direct_call_sites;
  for (llvm::User *user : interface_function->users()) {
    auto *call = llvm::dyn_cast<llvm::CallBase>(user);
    if (call == nullptr ||
        call->getCalledOperand()->stripPointerCasts() != interface_function) {
      continue;
    }
    direct_call_sites.push_back(call);
  }

  llvm::Function *implementation_function =
      clone_vm_implementation(*interface_function);
  if (implementation_function == nullptr) {
    return binding;
  }

  binding.interface_function = interface_function;
  binding.implementation_function = implementation_function;
  binding.state = &state;
  binding.wrapper_token = derive_vm_wrapper_token(interface_function->getName());

  std::uint64_t callsite_ordinal = 0;
  for (llvm::CallBase *call : direct_call_sites) {
    llvm::Function *caller = call->getFunction();
    if (caller == nullptr) {
      continue;
    }

    binding.call_sites.push_back(
        {.call = call,
         .hidden_token = derive_vm_hidden_token(interface_function->getName(),
                                                caller->getName(),
                                                callsite_ordinal++)});
  }

  rewrite_vm_interface_wrapper(*interface_function, *implementation_function,
                               binding.wrapper_token, mba_depth);
  return binding;
}

llvm::APInt derive_vm_target_key(const llvm::Function &function,
                                 llvm::IntegerType *ptr_int_type) {
  std::uint64_t key_word =
      static_cast<std::uint64_t>(llvm::hash_value(function.getName()));
  key_word ^= static_cast<std::uint64_t>(ptr_int_type->getBitWidth()) << 32;
  return llvm::APInt(ptr_int_type->getBitWidth(),
                     key_word == 0 ? 0xa55aa55aULL : key_word,
                     /*isSigned=*/false, /*implicitTrunc=*/true);
}

/// Sentinel stored in the lazy-resolution slot to indicate "not yet resolved".
/// Using ~key guarantees decoding would yield all-ones (never a valid code
/// pointer), while being trivially distinguishable from any real encoded target.
llvm::APInt derive_vm_target_sentinel(const llvm::APInt &key) {
  return ~key;
}

llvm::GlobalVariable *get_or_create_vm_target_global(llvm::Function &function) {
  llvm::Module *module = function.getParent();
  if (module == nullptr) {
    return nullptr;
  }

  const std::string global_name =
      ("__obf_vm_target_" + function.getName()).str();
  const llvm::DataLayout &data_layout = module->getDataLayout();
  auto *ptr_int_type =
      data_layout.getIntPtrType(module->getContext(), function.getAddressSpace());
  const llvm::APInt key = derive_vm_target_key(function, ptr_int_type);
  const llvm::APInt sentinel = derive_vm_target_sentinel(key);

  if (llvm::GlobalVariable *existing = module->getNamedGlobal(global_name)) {
    return existing;
  }

  auto *target_global = new llvm::GlobalVariable(
      *module, ptr_int_type, false, llvm::GlobalValue::PrivateLinkage,
      llvm::ConstantInt::get(ptr_int_type, sentinel), global_name);
  return target_global;
}

llvm::GlobalVariable *
get_or_create_vm_decode_key_global(llvm::Module &module,
                                   llvm::IntegerType *ptr_int_type,
                                   llvm::StringRef callee_name,
                                   const llvm::APInt &key) {
  const std::string global_name = ("__obf_vm_key_" + callee_name).str();
  if (auto *existing = module.getNamedGlobal(global_name)) {
    return existing;
  }

  return new llvm::GlobalVariable(module, ptr_int_type, /*isConstant=*/false,
                                  llvm::GlobalValue::PrivateLinkage,
                                  llvm::ConstantInt::get(ptr_int_type, key),
                                  global_name);
}

bool rewrite_calls_to_virtualized_function(
    const virtualized_function_binding &binding, std::uint32_t mba_depth) {
  if (binding.interface_function == nullptr ||
      binding.implementation_function == nullptr) {
    return false;
  }

  llvm::Function &function = *binding.interface_function;
  llvm::Function &implementation_function = *binding.implementation_function;
  llvm::GlobalVariable *target_global = get_or_create_vm_target_global(function);
  if (target_global == nullptr) {
    return false;
  }

  llvm::Module *module = function.getParent();
  if (module == nullptr) {
    return false;
  }

  auto *ptr_int_type = llvm::cast<llvm::IntegerType>(target_global->getValueType());
  const llvm::APInt key = derive_vm_target_key(function, ptr_int_type);
  const llvm::APInt sentinel = derive_vm_target_sentinel(key);

  // Compile-time salt for runtime-context mixing (distinct from key).
  const std::uint64_t raw_salt =
      static_cast<std::uint64_t>(llvm::hash_value(function.getName())) *
      0x9E3779B97F4A7C15ULL;
  const llvm::APInt salt(ptr_int_type->getBitWidth(),
                         raw_salt == 0 ? 0xC6EF3720ULL : raw_salt,
                         /*isSigned=*/false, /*implicitTrunc=*/true);

  bool changed = false;
  std::size_t callsite_index = 0;
  for (const virtualized_call_site &site : binding.call_sites) {
    llvm::CallBase *call = site.call;
    if (call == nullptr) {
      continue;
    }
    llvm::Function *caller = call->getFunction();
    if (caller == nullptr) {
      continue;
    }

    // Per-callee module-level key global (avoids alloca/domination issues
    // when control flattening hoists only leading allocas).
    llvm::GlobalVariable *decode_key_global = get_or_create_vm_decode_key_global(
        *module, ptr_int_type, function.getName(), key);

    // Split the block at the call to create room for the lazy-resolution
    // sentinel check and resolve path.
    llvm::BasicBlock *orig_bb = call->getParent();
    llvm::BasicBlock *call_bb = orig_bb->splitBasicBlock(
        call->getIterator(), (function.getName() + ".obf.call").str());
    orig_bb->getTerminator()->eraseFromParent();

    llvm::BasicBlock *resolve_bb = llvm::BasicBlock::Create(
        module->getContext(), (function.getName() + ".obf.resolve").str(),
        caller, call_bb);

    // --- Entry tail: load slot, compare against sentinel, branch ---
    llvm::IRBuilder<> entry_builder(orig_bb);
    llvm::Value *hidden_token = build_hidden_token_value(
        entry_builder, *caller, (function.getName() + ".obf.call").str(),
        site.hidden_token, mba_depth,
        0x700000ULL + static_cast<std::uint64_t>(callsite_index++));
    auto *encoded_check = entry_builder.CreateLoad(
        ptr_int_type, target_global,
        function.getName() + ".obf.check");
    auto *sentinel_const = llvm::ConstantInt::get(ptr_int_type, sentinel);
    auto *is_unresolved = entry_builder.CreateICmpEQ(
        encoded_check, sentinel_const,
        function.getName() + ".obf.unresolved");
    entry_builder.CreateCondBr(is_unresolved, resolve_bb, call_bb);

    // --- Resolve block: encode the implementation target and cache it ---
    llvm::IRBuilder<> resolve_builder(resolve_bb);
    auto *target_int = resolve_builder.CreatePtrToInt(
        &implementation_function, ptr_int_type,
        function.getName() + ".obf.real.int");
    llvm::Value *token_int = hidden_token;
    if (token_int->getType() != ptr_int_type) {
      token_int = resolve_builder.CreateZExtOrTrunc(
          token_int, ptr_int_type, function.getName() + ".obf.token.cast");
    }
    const std::string token_name = (function.getName() + ".obf.token").str();
    token_int = mba::entangle_value(
        resolve_builder, token_int,
        mba::builder_context{.entropy_anchor = mba::get_or_create_entropy_anchor(*module),
                             .seed_base = site.hidden_token,
                             .depth = mba_depth},
        0x710000ULL + site.hidden_token, token_name);
    auto *salt_const = llvm::ConstantInt::get(ptr_int_type, salt);
    auto *runtime_key = resolve_builder.CreateXor(
        token_int, salt_const,
        function.getName() + ".obf.rkey");
    auto *mixed = resolve_builder.CreateXor(
        target_int, runtime_key,
        function.getName() + ".obf.mixed");
    auto *unmixed = resolve_builder.CreateXor(
        mixed, runtime_key,
        function.getName() + ".obf.unmixed");
    auto *key_const = llvm::ConstantInt::get(ptr_int_type, key);
    auto *new_encoded = resolve_builder.CreateXor(
        unmixed, key_const,
        function.getName() + ".obf.resolved");
    resolve_builder.CreateStore(new_encoded, target_global);
    resolve_builder.CreateBr(call_bb);

    // --- Call block: merge encoded value, decode, indirect-call ---
    llvm::IRBuilder<> call_builder(call);
    auto *encoded_phi = call_builder.CreatePHI(
        ptr_int_type, 2,
        function.getName() + ".obf.encoded");
    encoded_phi->addIncoming(encoded_check, orig_bb);
    encoded_phi->addIncoming(new_encoded, resolve_bb);

    auto *opaque_key = call_builder.CreateLoad(
        ptr_int_type, decode_key_global,
        function.getName() + ".obf.key");
    llvm::Value *decoded_target =
        mba::create_xor(call_builder, encoded_phi, opaque_key,
                        mba::builder_context{.entropy_anchor = mba::get_or_create_entropy_anchor(*module),
                                             .seed_base = site.hidden_token ^ key.getLimitedValue(),
                                             .depth = mba_depth},
                        0x720000ULL + site.hidden_token,
                        (function.getName() + ".obf.decoded").str());
    llvm::Value *indirect_target = call_builder.CreateIntToPtr(
        decoded_target, call->getCalledOperand()->getType(),
        function.getName() + ".obf.indirect");

    llvm::SmallVector<llvm::Use *, 16> original_uses;
    for (llvm::Use &use : call->uses()) {
      original_uses.push_back(&use);
    }

    llvm::SmallVector<llvm::Value *, 8> arguments;
    arguments.reserve(call->arg_size() + 1);
    for (llvm::Use &argument : call->args()) {
      arguments.push_back(argument.get());
    }
    arguments.push_back(hidden_token);

    auto *rewritten_call = call_builder.CreateCall(
        implementation_function.getFunctionType(), indirect_target, arguments,
        call->getType()->isVoidTy() ? "" : function.getName() + ".obf.callsite");
    rewritten_call->setCallingConv(call->getCallingConv());
    rewritten_call->setAttributes(implementation_function.getAttributes());

    // Decode entangled return value for integer-returning functions.
    llvm::Type *call_ret_type = rewritten_call->getType();
    if (call_ret_type->isIntegerTy()) {
      llvm::GlobalVariable *retkey_global = module->getNamedGlobal(
          ("__obf_vm_retkey_" + function.getName()).str());
      if (retkey_global != nullptr) {
        // Insert decode instructions after the call.
        llvm::IRBuilder<> decode_builder(call);
        auto *retkey_load = decode_builder.CreateLoad(
            decode_builder.getInt64Ty(), retkey_global,
            function.getName() + ".obf.retkey");
        llvm::Value *retkey_trunc = retkey_load;
        if (call_ret_type != decode_builder.getInt64Ty()) {
          retkey_trunc = decode_builder.CreateTrunc(
              retkey_load, call_ret_type,
              function.getName() + ".obf.retkey.trunc");
        }
        mba::builder_context decode_context = mba::get_or_create_builder_context(
            *caller, (function.getName() + ".obf.ret").str(),
            site.hidden_token ^ 0x730000ULL);
        decode_context.depth = mba_depth;
        llvm::Value *decoded_ret = mba::create_xor(
            decode_builder, rewritten_call, retkey_trunc, decode_context,
            0x730000ULL + site.hidden_token,
            (function.getName() + ".obf.retdec").str());

        // Patch original uses to consume the decoded value.
        for (llvm::Use *use : original_uses) {
          use->set(decoded_ret);
        }
      } else {
        for (llvm::Use *use : original_uses) {
          use->set(rewritten_call);
        }
      }
    } else {
      for (llvm::Use *use : original_uses) {
        use->set(rewritten_call);
      }
    }

    call->eraseFromParent();

    changed = true;
  }

  return changed;
}

bool rewrite_calls_to_virtualized_functions(
    llvm::Module &, const virtualized_function_map &virtualized_functions,
    std::uint32_t mba_depth) {
  bool changed = false;
  for (const auto &entry : virtualized_functions) {
    changed |= rewrite_calls_to_virtualized_function(entry.second, mba_depth);
  }

  return changed;
}

virtualized_function_map
apply_vm_stage(const llvm::SmallVectorImpl<function_pipeline_state> &states,
               const obfuscation_config &config,
               const protection_level *only_level = nullptr) {
  virtualized_function_map virtualized_functions;

  for (const function_pipeline_state &state : states) {
    if (state.function == nullptr || state.function->isDeclaration() ||
        !state.report.decision.policy.allow_vm) {
      continue;
    }

    if (only_level && state.report.decision.policy.level != *only_level) {
      continue;
    }

    if (!vm::analyze_candidate(*state.function).eligible) {
      continue;
    }

    virtualized_function_binding binding =
        prepare_virtualized_function_binding(state, config.mba.depth);
    if (binding.implementation_function == nullptr) {
      continue;
    }

    vm::virtualization_options vm_options{.mba_depth = config.mba.depth,
                                          .hidden_token_handshake = true,
                                          .symbol_tag = state.function->getName().str()};
    vm_options.valid_hidden_tokens.push_back(binding.wrapper_token);
    for (const virtualized_call_site &site : binding.call_sites) {
      vm_options.valid_hidden_tokens.push_back(site.hidden_token);
    }

    const vm::virtualization_result result =
        vm::run_virtualization(*binding.implementation_function, vm_options);
    if (result.virtualized) {
      virtualized_functions[state.function->getName()] = std::move(binding);
    }
  }

  return virtualized_functions;
}

bool apply_string_encoding_stage(
    llvm::Module &module,
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config) {
  const llvm::StringMap<std::uint64_t> protected_functions =
      build_function_seed_map(states, [](const function_policy &policy) {
        return policy.allow_string_encoding;
      });

  const string_encoding_options options = build_string_encoding_options(config);
  const std::vector<string_encoding_result> results = run_string_encoding(
      module,
      [&](llvm::StringRef function_name) -> std::optional<std::uint64_t> {
        const auto iterator = protected_functions.find(function_name);
        if (iterator == protected_functions.end()) {
          return std::nullopt;
        }

        return iterator->second;
      },
      options, config.seed);

  return llvm::any_of(results, [](const string_encoding_result &result) {
    return result.applied;
  });
}

bool apply_constant_encoding_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions = nullptr) {
  bool changed = false;

  for (const function_pipeline_state &state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_constant_encoding ||
        state.report.decision.policy.level == protection_level::strong_vm) {
      continue;
    }

    const constant_encoding_options options =
        build_constant_encoding_options(config, state.report.decision);
    changed |= run_constant_encoding(*state.function, options,
                                     state.report.decision.seed)
                   .encoded_count > 0;
  }

  return changed;
}

bool apply_instruction_substitution_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions = nullptr) {
  bool changed = false;

  for (const function_pipeline_state &state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_instruction_substitution ||
        state.report.decision.policy.level == protection_level::strong_vm) {
      continue;
    }

    const instruction_substitution_options options =
        build_instruction_substitution_options(config, state.report.decision);
    changed |= run_instruction_substitution(*state.function, options)
                   .substitution_count > 0;
  }

  return changed;
}

bool apply_opaque_gep_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions = nullptr) {
  bool changed = false;

  for (const function_pipeline_state &state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_opaque_gep) {
      continue;
    }

    const opaque_gep_options options =
        build_opaque_gep_options(config, state.report.decision);
    changed |= run_opaque_gep(*state.function, options).lowered_count > 0;
  }

  return changed;
}

bool apply_instruction_substitution_to_functions(
    const virtualized_function_map &virtualized_functions,
    const obfuscation_config &config) {
  bool changed = false;

  for (const auto &entry : virtualized_functions) {
    llvm::Function *function = entry.second.implementation_function;
    if (function == nullptr || function->isDeclaration()) {
      continue;
    }

    if (entry.second.state == nullptr ||
        !entry.second.state->report.decision.policy.allow_instruction_substitution) {
      continue;
    }

    const instruction_substitution_options options =
        build_instruction_substitution_options(config,
                                              entry.second.state->report.decision);
    changed |= run_instruction_substitution(*function, options).substitution_count > 0;
  }

  return changed;
}

bool apply_opaque_gep_to_functions(
    const virtualized_function_map &virtualized_functions,
    const obfuscation_config &config) {
  bool changed = false;

  for (const auto &entry : virtualized_functions) {
    llvm::Function *function = entry.second.implementation_function;
    if (function == nullptr || function->isDeclaration()) {
      continue;
    }

    if (entry.second.state == nullptr ||
        !entry.second.state->report.decision.policy.allow_opaque_gep) {
      continue;
    }

    const opaque_gep_options options =
        build_opaque_gep_options(config, entry.second.state->report.decision);
    changed |= run_opaque_gep(*function, options).lowered_count > 0;
  }

  return changed;
}

bool apply_opaque_predicate_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions = nullptr) {
  bool changed = false;

  for (const function_pipeline_state &state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_opaque_predicates) {
      continue;
    }

    const opaque_predicate_options options =
        build_opaque_predicate_options(config, state.report.decision);
    changed |= run_opaque_predicates(*state.function, options).insertion_count > 0;
  }

  return changed;
}

llvm::StringSet<> apply_control_flattening_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions = nullptr) {
  llvm::StringSet<> flattened_functions;

  for (const function_pipeline_state &state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_flattening) {
      continue;
    }

    const control_flattening_options options =
        build_control_flattening_options(config, state.report.decision);
    const control_flattening_result result =
        run_control_flattening(*state.function, options);
    if (result.flattened) {
      flattened_functions.insert(state.function->getName());
    }
  }

  return flattened_functions;
}

llvm::StringSet<> apply_control_flattening_to_functions(
    const virtualized_function_map &virtualized_functions,
    const obfuscation_config &config) {
  llvm::StringSet<> flattened_functions;

  for (const auto &entry : virtualized_functions) {
    llvm::Function *function = entry.second.implementation_function;
    if (function == nullptr || function->isDeclaration()) {
      continue;
    }

    if (entry.second.state == nullptr ||
        !entry.second.state->report.decision.policy.allow_flattening) {
      continue;
    }

    const control_flattening_options options =
        build_control_flattening_options(config,
                                         entry.second.state->report.decision);
    const control_flattening_result result = run_control_flattening(*function, options);
    if (result.flattened) {
      flattened_functions.insert(function->getName());
    }
  }

  return flattened_functions;
}

bool apply_bogus_control_flow_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions = nullptr) {
  bool changed = false;

  for (const function_pipeline_state &state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_bogus_control_flow) {
      continue;
    }

    const bogus_control_flow_options options =
        build_bogus_control_flow_options(config, state.report.decision);
    changed |= run_bogus_control_flow(*state.function, options)
                   .insertion_count > 0;
  }

  return changed;
}

bool apply_bogus_control_flow_to_functions(
    const virtualized_function_map &virtualized_functions,
    const obfuscation_config &config) {
  bool changed = false;

  for (const auto &entry : virtualized_functions) {
    llvm::Function *function = entry.second.implementation_function;
    if (function == nullptr || function->isDeclaration()) {
      continue;
    }

    if (entry.second.state == nullptr ||
        !entry.second.state->report.decision.policy.allow_bogus_control_flow) {
      continue;
    }

    const bogus_control_flow_options options =
        build_bogus_control_flow_options(config,
                                         entry.second.state->report.decision);
    changed |= run_bogus_control_flow(*function, options).insertion_count > 0;
  }

  return changed;
}

llvm::StringSet<> collect_virtualized_function_names(
    const virtualized_function_map &virtualized_functions) {
  llvm::StringSet<> names;
  for (const auto &entry : virtualized_functions) {
    names.insert(entry.getKey());
    if (entry.second.implementation_function != nullptr) {
      names.insert(entry.second.implementation_function->getName());
    }
  }
  return names;
}

} // namespace

class feature_report_pass : public llvm::PassInfoMixin<feature_report_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    llvm::SmallVector<function_report_entry, 32> entries;
    entries.reserve(states.size());
    for (const function_pipeline_state &state : states) {
      entries.push_back(state.report);
    }

    const llvm::SmallVector<transform_report_entry, 64> transforms =
        build_transform_reports(module, states, config);

    llvm::outs() << format_feature_report(module.getName(), entries, transforms)
                 << '\n';
    return llvm::PreservedAnalyses::all();
  }
};

class block_split_pass : public llvm::PassInfoMixin<block_split_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    const bool changed = apply_block_split_stage(states, config);

    if (!changed) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);

    return llvm::PreservedAnalyses::none();
  }
};

class string_encoding_pass : public llvm::PassInfoMixin<string_encoding_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    const bool changed = apply_string_encoding_stage(module, states, config);

    if (!changed) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class vm_pass : public llvm::PassInfoMixin<vm_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    const virtualized_function_map virtualized_functions =
        apply_vm_stage(states, config);
    bool changed = !virtualized_functions.empty();
    changed |= rewrite_calls_to_virtualized_functions(module, virtualized_functions,
                                                      config.mba.depth);
    if (!changed) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class constant_encoding_pass : public llvm::PassInfoMixin<constant_encoding_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    const bool changed = apply_constant_encoding_stage(states, config);

    if (!changed) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class instruction_substitution_pass
    : public llvm::PassInfoMixin<instruction_substitution_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    const bool changed = apply_instruction_substitution_stage(states, config);
    if (!changed) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class opaque_gep_pass : public llvm::PassInfoMixin<opaque_gep_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    const bool changed = apply_opaque_gep_stage(states, config);
    if (!changed) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class control_flattening_pass
    : public llvm::PassInfoMixin<control_flattening_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    const llvm::StringSet<> flattened_functions =
        apply_control_flattening_stage(states, config);
    if (flattened_functions.empty()) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class opaque_predicate_pass
    : public llvm::PassInfoMixin<opaque_predicate_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    const bool changed = apply_opaque_predicate_stage(states, config);
    if (!changed) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class bogus_control_flow_pass
    : public llvm::PassInfoMixin<bogus_control_flow_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    const bool changed = apply_bogus_control_flow_stage(states, config);
    if (!changed) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class safe_pipeline_pass : public llvm::PassInfoMixin<safe_pipeline_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    bool changed = false;

    // Phase 1: VM for vm-only functions and strong_vm functions on pristine IR.
    constexpr protection_level vm_level = protection_level::vm;
    const virtualized_function_map vm_only = apply_vm_stage(states, config, &vm_level);
    changed |= !vm_only.empty();
    changed |= rewrite_calls_to_virtualized_functions(module, vm_only,
                                                      config.mba.depth);

    constexpr protection_level strong_vm_level = protection_level::strong_vm;
    const virtualized_function_map strong_vm_virtualized =
        apply_vm_stage(states, config, &strong_vm_level);
    changed |= !strong_vm_virtualized.empty();
    changed |= rewrite_calls_to_virtualized_functions(module, strong_vm_virtualized,
                                                      config.mba.depth);

    // Phase 2: Classical transforms for non-VM functions only.
    changed |= apply_string_encoding_stage(module, states, config);
    llvm::StringSet<> all_vm_virtualized = collect_virtualized_function_names(vm_only);
    const llvm::StringSet<> strong_vm_names =
        collect_virtualized_function_names(strong_vm_virtualized);
    for (const auto &entry : strong_vm_names) {
      all_vm_virtualized.insert(entry.getKey());
    }

    changed |= apply_constant_encoding_stage(states, config, &all_vm_virtualized);
    changed |= apply_opaque_gep_stage(states, config, &all_vm_virtualized);
    changed |= apply_instruction_substitution_stage(states, config, &all_vm_virtualized);
    changed |= apply_opaque_predicate_stage(states, config, &all_vm_virtualized);
    const llvm::StringSet<> flattened_functions =
        apply_control_flattening_stage(states, config, &all_vm_virtualized);
    changed |= !flattened_functions.empty();
    changed |= apply_bogus_control_flow_stage(states, config, &all_vm_virtualized);

    // Phase 3: Block split for remaining classical functions only.
    llvm::StringSet<> block_split_skips;
    for (const auto &entry : all_vm_virtualized) {
      block_split_skips.insert(entry.getKey());
    }
    for (const auto &entry : flattened_functions) {
      block_split_skips.insert(entry.getKey());
    }
    changed |= apply_block_split_stage(states, config, &block_split_skips);

    // Phase 4: Harden only the generated VM infrastructure for strong_vm.
    changed |= apply_opaque_gep_to_functions(strong_vm_virtualized, config);
    llvm::StringSet<> strong_vm_flattened =
        apply_control_flattening_to_functions(strong_vm_virtualized, config);
    changed |= !strong_vm_flattened.empty();
    changed |=
        apply_instruction_substitution_to_functions(strong_vm_virtualized, config);
    changed |= apply_bogus_control_flow_to_functions(strong_vm_virtualized,
                                                     config);

    if (!changed) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

} // namespace obf

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "obf_plugin", "0.1",
          [](llvm::PassBuilder &pass_builder) {
            pass_builder.registerPipelineParsingCallback(
                [](llvm::StringRef name, llvm::ModulePassManager &module_pm,
                   llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
                  if (name == "obf-feature-report") {
                    module_pm.addPass(obf::feature_report_pass());
                    return true;
                  }

                  if (name == "obf-block-split" ||
                      name == "obf-split-scaffold") {
                    module_pm.addPass(obf::block_split_pass());
                    return true;
                  }

                  if (name == "obf-string-encode") {
                    module_pm.addPass(obf::string_encoding_pass());
                    return true;
                  }

                  if (name == "obf-vm") {
                    module_pm.addPass(obf::vm_pass());
                    return true;
                  }

                  if (name == "obf-constant-encode") {
                    module_pm.addPass(obf::constant_encoding_pass());
                    return true;
                  }

                  if (name == "obf-instruction-substitute") {
                    module_pm.addPass(obf::instruction_substitution_pass());
                    return true;
                  }

                  if (name == "obf-opaque-gep") {
                    module_pm.addPass(obf::opaque_gep_pass());
                    return true;
                  }

                  if (name == "obf-control-flatten") {
                    module_pm.addPass(obf::control_flattening_pass());
                    return true;
                  }

                  if (name == "obf-opaque-preds") {
                    module_pm.addPass(obf::opaque_predicate_pass());
                    return true;
                  }

                  if (name == "obf-bogus-cf") {
                    module_pm.addPass(obf::bogus_control_flow_pass());
                    return true;
                  }

                  if (name == "obf-safe-pipeline") {
                    module_pm.addPass(obf::safe_pipeline_pass());
                    return true;
                  }

                  return false;
                });
          }};
}
