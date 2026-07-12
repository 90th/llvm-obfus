#include "obf/plugin/obfuscator_plugin_internal.h"

#include "obf/report/function_report.h"

// Transform headers needed for pass function implementations
#include "obf/transforms/artifact_cleanup.h"
#include "obf/transforms/block_split.h"
#include "obf/transforms/bogus_control_flow.h"
#include "obf/transforms/constant_encoding.h"
#include "obf/transforms/control_flattening.h"
#include "obf/transforms/function_outlining.h"
#include "obf/transforms/instruction_substitution.h"
#include "obf/transforms/opaque_gep.h"
#include "obf/transforms/opaque_predicates.h"
#include "obf/transforms/string_encoding.h"
#include "obf/transforms/entropy_initialization.h"
#include "obf/transforms/indirect_dispatch.h"

// Note: apply_cfg_state_cleanup_stage() is defined in plugin_pipeline.cpp (no header needed)

#include "llvm/ADT/StringSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Transforms/Utils/Mem2Reg.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace obf {

namespace {

llvm::cl::opt<std::string> AuditOutPath(
    "obf-audit-out", llvm::cl::desc("Path to write obf-audit JSON output"),
    llvm::cl::init(""));

struct AuditRow {
  const llvm::Function* function = nullptr;
  protection_level final_level = protection_level::none;
  llvm::StringRef source_of_truth;
};

struct AuditColumnWidths {
  std::size_t function = 8;
  std::size_t level = 11;
  std::size_t source = 15;
};

llvm::StringRef ToStringRef(protection_level level) {
  const std::string_view text = to_string(level);
  return {text.data(), text.size()};
}

llvm::StringRef DescribeBaseSource(policy_source source) {
  switch (source) {
    case policy_source::default_policy:
      return "yaml default policy";
    case policy_source::automatic_analysis:
      return "automatic analysis";
    case policy_source::config_rule:
      return "yaml target rule";
    case policy_source::source_annotation:
      return "source annotation (OBF_ANNOTATE)";
    case policy_source::explicit_override:
      return "yaml explicit override";
  }

  return "yaml default policy";
}

std::optional<llvm::StringRef> DescribeLevelDeterminingClause(llvm::StringRef clause) {
  if (clause.starts_with("declaration forced none")) {
    return llvm::StringRef("implicit (declaration forced none)");
  }

  if (clause.starts_with("risky features downgraded ")) {
    return llvm::StringRef("automatic analysis (downgrade)");
  }

  if (clause.starts_with("address-taken forced ")) {
    return llvm::StringRef("automatic analysis (address-taken)");
  }

  if (clause.starts_with("minimum security floor raised to ")) {
    return llvm::StringRef("automatic analysis (minimum security floor)");
  }

  if (clause.starts_with("orchestrator promotion raised to ")) {
    return llvm::StringRef("automatic analysis (orchestrator promotion)");
  }

  return std::nullopt;
}

llvm::StringRef ResolveSourceOfTruth(const policy_decision& decision) {
  llvm::StringRef remaining = decision.detail;
  while (!remaining.empty()) {
    const std::size_t separator = remaining.rfind("; ");
    const llvm::StringRef clause = separator == llvm::StringRef::npos
                                       ? remaining
                                       : remaining.drop_front(separator + 2);
    if (const std::optional<llvm::StringRef> label = DescribeLevelDeterminingClause(clause)) {
      return *label;
    }

    if (separator == llvm::StringRef::npos) { break; }
    remaining = remaining.take_front(separator);
  }

  return DescribeBaseSource(decision.source);
}

std::string BuildFunctionDisplayName(llvm::StringRef function_name) {
  std::string display_name;
  display_name.reserve(function_name.size() + 2);
  display_name.append(function_name.begin(), function_name.end());
  display_name += "()";
  return display_name;
}

std::size_t GetFunctionDisplayWidth(const llvm::Function& function) {
  return function.getName().size() + 2;
}

void WritePadding(llvm::raw_ostream& stream, std::size_t padding) {
  for (std::size_t index = 0; index < padding; ++index) { stream << ' '; }
}

void WritePaddedCell(llvm::raw_ostream& stream, llvm::StringRef text, std::size_t width) {
  stream << text;
  if (text.size() < width) { WritePadding(stream, width - text.size()); }
}

void WritePaddedFunctionCell(llvm::raw_ostream& stream,
                             const llvm::Function& function,
                             std::size_t width) {
  stream << function.getName() << "()";
  const std::size_t display_width = GetFunctionDisplayWidth(function);
  if (display_width < width) { WritePadding(stream, width - display_width); }
}

AuditColumnWidths ComputeAuditColumnWidths(const llvm::SmallVectorImpl<AuditRow>& rows) {
  AuditColumnWidths widths;
  for (const AuditRow& row : rows) {
    if (row.function == nullptr) { continue; }

    widths.function = std::max(widths.function, GetFunctionDisplayWidth(*row.function));
    widths.level = std::max(widths.level, ToStringRef(row.final_level).size());
    widths.source = std::max(widths.source, row.source_of_truth.size());
  }

  return widths;
}

void PrintAuditSeparator(llvm::raw_ostream& stream, const AuditColumnWidths& widths) {
  const std::size_t separator_width = widths.function + widths.level + widths.source + 6;
  for (std::size_t index = 0; index < separator_width; ++index) { stream << '-'; }
  stream << '\n';
}

void PrintAuditTable(const llvm::SmallVectorImpl<AuditRow>& rows) {
  llvm::raw_ostream& stream = llvm::outs();
  const AuditColumnWidths widths = ComputeAuditColumnWidths(rows);

  stream << "[ llvm-obfus policy resolution ]\n";
  WritePaddedCell(stream, "function", widths.function);
  stream << " | ";
  WritePaddedCell(stream, "final level", widths.level);
  stream << " | ";
  stream << "source of truth\n";
  PrintAuditSeparator(stream, widths);

  for (const AuditRow& row : rows) {
    if (row.function == nullptr) { continue; }

    WritePaddedFunctionCell(stream, *row.function, widths.function);
    stream << " | ";
    WritePaddedCell(stream, ToStringRef(row.final_level), widths.level);
    stream << " | ";
    stream << row.source_of_truth << '\n';
  }
}

void WriteAuditJson(llvm::StringRef output_path,
                    llvm::StringRef module_name,
                    const llvm::SmallVectorImpl<AuditRow>& rows) {
  llvm::json::Array functions_json;
  for (const AuditRow& row : rows) {
    if (row.function == nullptr) { continue; }

    llvm::json::Object function_json;
    function_json["function"] = BuildFunctionDisplayName(row.function->getName());
    function_json["final_level"] = ToStringRef(row.final_level);
    function_json["source_of_truth"] = row.source_of_truth;
    functions_json.push_back(llvm::json::Value(std::move(function_json)));
  }

  llvm::json::Object root;
  root["schema"] = "obf.audit.v1";
  root["title"] = "llvm-obfus policy resolution";
  root["module"] = module_name;
  root["function_count"] = static_cast<std::int64_t>(functions_json.size());
  root["functions"] = llvm::json::Value(std::move(functions_json));

  std::error_code error_code;
  llvm::raw_fd_ostream stream(output_path, error_code, llvm::sys::fs::OF_Text);
  if (error_code) {
    std::string message = "failed to open obf-audit JSON output '";
    message += output_path.str();
    message += "': ";
    message += error_code.message();
    llvm::report_fatal_error(llvm::StringRef(message));
  }

  stream << llvm::json::Value(std::move(root));
  stream.close();
  if (stream.has_error()) {
    std::string message = "failed to write obf-audit JSON output '";
    message += output_path.str();
    message += "'";
    llvm::report_fatal_error(llvm::StringRef(message));
  }
}

class AuditResolver {
 public:
  explicit AuditResolver(llvm::Module& module)
      : states_(build_pipeline_state(module, load_active_config())) {}

  llvm::SmallVector<AuditRow, 32> Resolve() const {
    llvm::SmallVector<AuditRow, 32> rows;
    rows.reserve(states_.size());
    for (const function_pipeline_state& state : states_) {
      rows.push_back({.function = state.function,
                      .final_level = state.report.decision.policy.level,
                      .source_of_truth = ResolveSourceOfTruth(state.report.decision)});
    }

    return rows;
  }

 private:
  llvm::SmallVector<function_pipeline_state, 32> states_;
};

// Boilerplate helpers for pass execution pattern:
// - run_stateful_stage: For transforming passes that use function_pipeline_state
// - run_config_stage: For passes that only need config, not function state
//
// Exceptions (direct config/state loading, not using helpers):
// - feature_report_pass: Read-only reporting pass; doesn't transform IR; no bool return
// - EntropyInitializationPass: Creates new functions; can't use standard state pattern
// - CfgStateCleanupPass: Module-level cleanup; doesn't use function_pipeline_state
// - safe_pipeline_pass: Complex orchestrator with custom control flow; too specialized

template <typename StageFn>
llvm::PreservedAnalyses run_stateful_stage(llvm::Module& module, StageFn&& stage) {
  const obfuscation_config config = load_active_config();
  const llvm::SmallVector<function_pipeline_state, 32> states =
      build_pipeline_state(module, config);

  if (!std::forward<StageFn>(stage)(module, states, config)) {
    return llvm::PreservedAnalyses::all();
  }

  verify_changed_module(module);
  return llvm::PreservedAnalyses::none();
}

template <typename StageFn>
llvm::PreservedAnalyses run_config_stage(llvm::Module& module, StageFn&& stage) {
  const obfuscation_config config = load_active_config();
  if (!std::forward<StageFn>(stage)(module, config)) { return llvm::PreservedAnalyses::all(); }

  verify_changed_module(module);
  return llvm::PreservedAnalyses::none();
}

class feature_report_pass : public llvm::PassInfoMixin<feature_report_pass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    const obfuscation_config config = load_active_config();
    llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    for (auto& state : states) {
      if (state.function != nullptr) {
        state.mba_counts = mba::get_mba_counters(*state.function);
      }
    }

    llvm::SmallVector<function_report_entry, 32> entries;
    entries.reserve(states.size());
    for (const function_pipeline_state& state : states) { entries.push_back(state.report); }

    const llvm::SmallVector<transform_report_entry, 64> transforms =
        build_transform_reports(module, states, config);

    llvm::outs() << format_feature_report(module.getName(), entries, transforms) << '\n';
    return llvm::PreservedAnalyses::all();
  }
};

class ObfAuditPass : public llvm::PassInfoMixin<ObfAuditPass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    const AuditResolver resolver(module);
    const llvm::SmallVector<AuditRow, 32> rows = resolver.Resolve();

    PrintAuditTable(rows);
    if (!AuditOutPath.empty()) { WriteAuditJson(AuditOutPath, module.getName(), rows); }

    return llvm::PreservedAnalyses::all();
  }
};

class block_split_pass : public llvm::PassInfoMixin<block_split_pass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    return run_stateful_stage(
        module,
        [](llvm::Module&,
           const llvm::SmallVectorImpl<function_pipeline_state>& states,
           const obfuscation_config& config) { return apply_block_split_stage(states, config); });
  }
};

class EntropyInitializationPass : public llvm::PassInfoMixin<EntropyInitializationPass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    if (!apply_entropy_initialization_stage(module, get_obf_seed_override())) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class CfgStateCleanupPass : public llvm::PassInfoMixin<CfgStateCleanupPass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    if (!apply_cfg_state_cleanup_stage(module)) { return llvm::PreservedAnalyses::all(); }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class ArtifactCleanupPass : public llvm::PassInfoMixin<ArtifactCleanupPass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    return run_config_stage(module, apply_artifact_cleanup_stage);
  }
};

class string_encoding_pass : public llvm::PassInfoMixin<string_encoding_pass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    return run_stateful_stage(module,
                              [](llvm::Module& current_module,
                                 const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                 const obfuscation_config& config) {
                                return apply_string_encoding_stage(current_module, states, config);
                               });
  }
};

class indirect_dispatch_pass : public llvm::PassInfoMixin<indirect_dispatch_pass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    return run_stateful_stage(
        module,
        [](llvm::Module&,
           const llvm::SmallVectorImpl<function_pipeline_state>& states,
           const obfuscation_config& config) {
          return apply_indirect_dispatch_stage(states, config);
        });
  }
};

class vm_pass : public llvm::PassInfoMixin<vm_pass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    return run_stateful_stage(module,
                              [](llvm::Module& current_module,
                                 const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                 const obfuscation_config& config) {
                                const virtualized_function_map virtualized_functions =
                                    apply_vm_stage(states, config);
                                bool changed = !virtualized_functions.empty();
                                changed |= rewrite_calls_to_virtualized_functions(
                                    current_module, virtualized_functions, config.mba.depth);
                                return changed;
                              });
  }
};

class constant_encoding_pass : public llvm::PassInfoMixin<constant_encoding_pass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    return run_stateful_stage(module,
                              [](llvm::Module& current_module,
                                 const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                  const obfuscation_config& config) {
                                return apply_constant_encoding_stage(current_module, states, config);
                              });
  }
};

class instruction_substitution_pass : public llvm::PassInfoMixin<instruction_substitution_pass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    return run_stateful_stage(module,
                              [](llvm::Module&,
                                 const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                 const obfuscation_config& config) {
                                return apply_instruction_substitution_stage(states, config);
                              });
  }
};

class opaque_gep_pass : public llvm::PassInfoMixin<opaque_gep_pass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    return run_stateful_stage(
        module,
        [](llvm::Module&,
           const llvm::SmallVectorImpl<function_pipeline_state>& states,
           const obfuscation_config& config) { return apply_opaque_gep_stage(states, config); });
  }
};

class function_outlining_pass : public llvm::PassInfoMixin<function_outlining_pass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    return run_stateful_stage(module,
                              [](llvm::Module&,
                                 const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                 const obfuscation_config& config) {
                                return apply_function_outlining_stage(states, config);
                              });
  }
};

class control_flattening_pass : public llvm::PassInfoMixin<control_flattening_pass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    return run_stateful_stage(module,
                              [](llvm::Module&,
                                 const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                 const obfuscation_config& config) {
                                const llvm::StringSet<> flattened_functions =
                                    apply_control_flattening_stage(states, config);
                                return !flattened_functions.empty();
                              });
  }
};

class opaque_predicate_pass : public llvm::PassInfoMixin<opaque_predicate_pass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    return run_stateful_stage(module,
                              [](llvm::Module&,
                                 const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                 const obfuscation_config& config) {
                                return apply_opaque_predicate_stage(states, config);
                              });
  }
};

class bogus_control_flow_pass : public llvm::PassInfoMixin<bogus_control_flow_pass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    return run_stateful_stage(module,
                              [](llvm::Module&,
                                 const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                 const obfuscation_config& config) {
                                return apply_bogus_control_flow_stage(states, config);
                              });
  }
};

class prepare_o0_pass : public llvm::PassInfoMixin<prepare_o0_pass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager& mam) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    // Run PromotePass (mem2reg) strictly on functions targeted for obfuscation
    // before running the obfuscation pipeline, preparing raw AST allocas into SSA form.
    llvm::FunctionPassManager fpm;
    fpm.addPass(llvm::PromotePass());
    auto& fam = mam.getResult<llvm::FunctionAnalysisManagerModuleProxy>(module).getManager();
    bool changed = false;
    for (const auto& state : states) {
      if (state.report.decision.policy.level != protection_level::none && state.function != nullptr) {
        llvm::PreservedAnalyses pa = fpm.run(*state.function, fam);
        if (!pa.areAllPreserved()) { changed = true; }
      }
    }
    return changed ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();
  }
};

std::size_t count_states_at_level(const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                  protection_level level) {
  std::size_t count = 0;
  for (const function_pipeline_state& state : states) {
    if (state.function != nullptr && !state.function->isDeclaration() &&
        state.report.decision.policy.level == level) {
      ++count;
    }
  }
  return count;
}

void emit_progress_warning_if_enabled(const obfuscation_config& config,
                                      llvm::StringRef phase,
                                      std::size_t count) {
  if (!config.emit_progress_warnings || count == 0) { return; }
  llvm::errs() << "llvm-obfus: warning: " << phase << " for " << count
               << " function(s); this can take a while\n";
}

class safe_pipeline_pass : public llvm::PassInfoMixin<safe_pipeline_pass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager& mam) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);




    bool changed = apply_entropy_initialization_stage(module, get_obf_seed_override());

    constexpr protection_level vm_level = protection_level::vm;
    const virtualized_function_map vm_only = apply_vm_stage(states, config, &vm_level);
    changed |= !vm_only.empty();
    changed |= rewrite_calls_to_virtualized_functions(module, vm_only, config.mba.depth);

    constexpr protection_level strong_vm_level = protection_level::strong_vm;
    const std::size_t selected_strong_vm_count =
        count_states_at_level(states, protection_level::strong_vm);
    emit_progress_warning_if_enabled(config,
                                     "starting strong_vm lowering",
                                     selected_strong_vm_count);
    const virtualized_function_map strong_vm_virtualized =
        apply_vm_stage(states, config, &strong_vm_level);
    changed |= !strong_vm_virtualized.empty();
    changed |=
        rewrite_calls_to_virtualized_functions(module, strong_vm_virtualized, config.mba.depth);

    virtualized_function_map post_vm_virtualized = vm_only;
    for (const auto& entry : strong_vm_virtualized) {
      post_vm_virtualized[entry.getKey()] = entry.second;
    }

    const llvm::SmallVector<function_pipeline_state, 32> post_vm_states =
        build_pipeline_state(module, config);

    changed |= apply_string_encoding_stage(module, post_vm_states, config, &post_vm_virtualized);
    llvm::StringSet<> all_vm_virtualized = collect_virtualized_function_names(vm_only);
    const llvm::StringSet<> strong_vm_names =
        collect_virtualized_function_names(strong_vm_virtualized);
    for (const auto& entry : strong_vm_names) { all_vm_virtualized.insert(entry.getKey()); }
    include_vm_parent_functions(all_vm_virtualized, strong_vm_virtualized);
    const llvm::StringSet<> preserved_site_callers =
        collect_preserved_site_caller_names(post_vm_virtualized);
    for (const auto& caller_entry : preserved_site_callers) {
      all_vm_virtualized.insert(caller_entry.getKey());
    }

    changed |= apply_constant_encoding_stage(module, post_vm_states, config, &all_vm_virtualized);
    changed |= apply_opaque_gep_stage(post_vm_states, config, &all_vm_virtualized);
    changed |= apply_instruction_substitution_stage(post_vm_states, config, &all_vm_virtualized);
    changed |= apply_opaque_predicate_stage(post_vm_states, config, &all_vm_virtualized);
    const llvm::StringSet<> flattened_functions =
        apply_control_flattening_stage(post_vm_states, config, &all_vm_virtualized);
    changed |= !flattened_functions.empty();
    changed |= apply_function_outlining_stage(post_vm_states, config, &all_vm_virtualized);
    changed |= apply_bogus_control_flow_stage(post_vm_states, config, &all_vm_virtualized);

    llvm::StringSet<> block_split_skips;
    for (const auto& entry : all_vm_virtualized) { block_split_skips.insert(entry.getKey()); }
    for (const auto& entry : flattened_functions) { block_split_skips.insert(entry.getKey()); }
    changed |= apply_block_split_stage(post_vm_states, config, &block_split_skips);

    emit_progress_warning_if_enabled(config,
                                     "starting strong_vm hardening",
                                     strong_vm_virtualized.size());
    changed |= apply_opaque_gep_to_functions(strong_vm_virtualized, config);
    llvm::StringSet<> strong_vm_flattened =
        apply_control_flattening_to_functions(strong_vm_virtualized, config);
    changed |= !strong_vm_flattened.empty();
    changed |= apply_function_outlining_to_functions(strong_vm_virtualized, config);
    changed |= apply_instruction_substitution_to_functions(strong_vm_virtualized, config);
    changed |= apply_bogus_control_flow_to_functions(strong_vm_virtualized, config);

    // Final late-stage sequence: remove CFG placeholders, lower remaining
    // dispatch hubs, enforce invariants, then strip markers.
    changed |= apply_cfg_state_cleanup_stage(module);
    changed |= apply_indirect_dispatch_stage(post_vm_states, config, &all_vm_virtualized);
    changed |= apply_indirect_dispatch_to_functions(post_vm_virtualized, config);
    changed |= enforce_security_gates(module, states, post_vm_virtualized, config);
    changed |= apply_artifact_cleanup_stage(module, config);

    if (!changed) { return llvm::PreservedAnalyses::all(); }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

}  // namespace

}  // namespace obf

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "obf_plugin", "0.1", [](llvm::PassBuilder& pass_builder) {
            pass_builder.registerPipelineParsingCallback(
                [](llvm::StringRef name,
                   llvm::ModulePassManager& module_pm,
                   llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
                  if (name == "obf-feature-report") {
                    module_pm.addPass(obf::feature_report_pass());
                    return true;
                  }

                  if (name == "obf-audit") {
                    module_pm.addPass(obf::ObfAuditPass());
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

                  if (name == "obf-block-split" || name == "obf-split-scaffold") {
                    module_pm.addPass(obf::block_split_pass());
                    return true;
                  }

                  if (name == "obf-string-encode") {
                    module_pm.addPass(obf::string_encoding_pass());
                    return true;
                  }

                  if (name == "obf-indirect-dispatch") {
                    module_pm.addPass(obf::indirect_dispatch_pass());
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

            pass_builder.registerOptimizerLastEPCallback(
                [](llvm::ModulePassManager& module_pm, llvm::OptimizationLevel level, llvm::ThinOrFullLTOPhase phase) {
                  if (!obf::is_obfuscation_enabled()) { return; }
                  if (level != llvm::OptimizationLevel::O0 && phase != llvm::ThinOrFullLTOPhase::FullLTOPostLink) {
                    module_pm.addPass(obf::safe_pipeline_pass());
                  }
                });

            pass_builder.registerFullLinkTimeOptimizationLastEPCallback(
                [](llvm::ModulePassManager& module_pm, llvm::OptimizationLevel level) {
                  if (!obf::is_obfuscation_enabled()) { return; }
                  module_pm.addPass(obf::safe_pipeline_pass());
                });

            pass_builder.registerPipelineStartEPCallback(
                [](llvm::ModulePassManager& module_pm, llvm::OptimizationLevel level) {
                  if (!obf::is_obfuscation_enabled()) { return; }
                  if (level == llvm::OptimizationLevel::O0) {
                    module_pm.addPass(obf::prepare_o0_pass());
                    module_pm.addPass(obf::safe_pipeline_pass());
                  }
                });
          }};
}
