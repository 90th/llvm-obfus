#include "obf/plugin/obfuscator_plugin_internal.h"

#include "obf/report/function_report.h"

#include "llvm/ADT/StringSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

namespace obf {

namespace {

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

class EntropyInitializationPass
    : public llvm::PassInfoMixin<EntropyInitializationPass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    if (!apply_entropy_initialization_stage(module)) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class CfgStateCleanupPass : public llvm::PassInfoMixin<CfgStateCleanupPass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    if (!apply_cfg_state_cleanup_stage(module)) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class ArtifactCleanupPass : public llvm::PassInfoMixin<ArtifactCleanupPass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    if (!apply_artifact_cleanup_stage(module, config)) {
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

class function_outlining_pass
    : public llvm::PassInfoMixin<function_outlining_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    const bool changed = apply_function_outlining_stage(states, config);
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

    bool changed = apply_entropy_initialization_stage(module);

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

    virtualized_function_map post_vm_virtualized = vm_only;
    for (const auto &entry : strong_vm_virtualized) {
      post_vm_virtualized[entry.getKey()] = entry.second;
    }

    const llvm::SmallVector<function_pipeline_state, 32> post_vm_states =
        build_pipeline_state(module, config);

    changed |= apply_string_encoding_stage(module, post_vm_states, config,
                                           &post_vm_virtualized);
    llvm::StringSet<> all_vm_virtualized = collect_virtualized_function_names(vm_only);
    const llvm::StringSet<> strong_vm_names =
        collect_virtualized_function_names(strong_vm_virtualized);
    for (const auto &entry : strong_vm_names) {
      all_vm_virtualized.insert(entry.getKey());
    }
    include_vm_parent_functions(all_vm_virtualized, strong_vm_virtualized);

    changed |= apply_constant_encoding_stage(post_vm_states, config, &all_vm_virtualized);
    changed |= apply_opaque_gep_stage(post_vm_states, config, &all_vm_virtualized);
    changed |= apply_instruction_substitution_stage(post_vm_states, config,
                                                    &all_vm_virtualized);
    changed |= apply_opaque_predicate_stage(post_vm_states, config,
                                            &all_vm_virtualized);
    const llvm::StringSet<> flattened_functions =
        apply_control_flattening_stage(post_vm_states, config, &all_vm_virtualized);
    changed |= !flattened_functions.empty();
    changed |= apply_cfg_state_cleanup_stage(module);
    changed |= apply_function_outlining_stage(post_vm_states, config,
                                              &all_vm_virtualized);
    changed |= apply_bogus_control_flow_stage(post_vm_states, config,
                                              &all_vm_virtualized);

    llvm::StringSet<> block_split_skips;
    for (const auto &entry : all_vm_virtualized) {
      block_split_skips.insert(entry.getKey());
    }
    for (const auto &entry : flattened_functions) {
      block_split_skips.insert(entry.getKey());
    }
    changed |= apply_block_split_stage(post_vm_states, config, &block_split_skips);

    changed |= apply_opaque_gep_to_functions(strong_vm_virtualized, config);
    llvm::StringSet<> strong_vm_flattened =
        apply_control_flattening_to_functions(strong_vm_virtualized, config);
    changed |= !strong_vm_flattened.empty();
    changed |= apply_function_outlining_to_functions(strong_vm_virtualized, config);
    changed |=
        apply_instruction_substitution_to_functions(strong_vm_virtualized, config);
    changed |= apply_bogus_control_flow_to_functions(strong_vm_virtualized,
                                                     config);
    changed |= enforce_security_gates(module, states, post_vm_virtualized, config);
    changed |= apply_artifact_cleanup_stage(module, config);

    if (!changed) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

} // namespace

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

                  if (name == "obf-entropy-init") {
                    module_pm.addPass(obf::EntropyInitializationPass());
                    return true;
                  }

                  if (name == "obf-cfg-state-cleanup") {
                    module_pm.addPass(obf::CfgStateCleanupPass());
                    return true;
                  }

                  if (name == "obf-artifact-cleanup") {
                    module_pm.addPass(obf::ArtifactCleanupPass());
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

                  if (name == "obf-function-outline") {
                    module_pm.addPass(obf::function_outlining_pass());
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
