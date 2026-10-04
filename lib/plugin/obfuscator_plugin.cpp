#include "obf/plugin/obfuscator_plugin_internal.h"
#include "obf/policy/policy_engine.h"

#include "obf/report/function_report.h"
#include "obf/report/coverage_report.h"
#include "obf/support/stable_hash.h"

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
#include "obf/transforms/zero_comparison.h"
#include "obf/transforms/self_checksum.h"

// Note: apply_cfg_state_cleanup_stage() is defined in plugin_pipeline.cpp (no header needed)

#include "llvm/ADT/StringSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#if __has_include(<llvm/Plugins/PassPlugin.h>)
#include "llvm/Plugins/PassPlugin.h"
#else
#include "llvm/Passes/PassPlugin.h"
#endif
#include "llvm/Transforms/Scalar/SROA.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#if defined(_WIN32) || defined(__CYGWIN__)
#define OBF_PLUGIN_EXPORT
#elif defined(__GNUC__) || defined(__clang__)
#define OBF_PLUGIN_EXPORT __attribute__((visibility("default")))
#else
#define OBF_PLUGIN_EXPORT
#endif

namespace obf {

namespace {

std::optional<std::string> get_environment_value(const char* name) {
#if defined(_WIN32)
  char* value = nullptr;
  std::size_t length = 0;
  if (_dupenv_s(&value, &length, name) != 0 || value == nullptr) { return std::nullopt; }

  const std::unique_ptr<char, decltype(&std::free)> owned_value(value, &std::free);
  return std::string(owned_value.get(), length == 0 ? 0 : length - 1);
#else
  if (const char* value = std::getenv(name)) { return std::string(value); }
  return std::nullopt;
#endif
}

#if !defined(_WIN32)
llvm::cl::opt<std::string> AuditOutPath("obf-audit-out",
                                        llvm::cl::desc("Path to write obf-audit JSON output"),
                                        llvm::cl::init(""));
#endif

struct AuditRow {
  const llvm::Function* function = nullptr;
  protection_level policy_level = protection_level::none;
  llvm::StringRef source_of_truth;
  const policy_decision* decision = nullptr;
};

struct AuditColumnWidths {
  std::size_t function = 8;
  std::size_t level = 12;
  std::size_t source = 17;
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
    const llvm::StringRef clause =
        separator == llvm::StringRef::npos ? remaining : remaining.drop_front(separator + 2);
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
    widths.level = std::max(widths.level, ToStringRef(row.policy_level).size());
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
  WritePaddedCell(stream, "policy level", widths.level);
  stream << " | ";
  stream << "resolution source\n";
  PrintAuditSeparator(stream, widths);

  for (const AuditRow& row : rows) {
    if (row.function == nullptr) { continue; }

    WritePaddedFunctionCell(stream, *row.function, widths.function);
    stream << " | ";
    WritePaddedCell(stream, ToStringRef(row.policy_level), widths.level);
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
    function_json["policy"] = build_policy_report(*row.decision);
    function_json["resolution_source"] = row.source_of_truth;
    functions_json.push_back(llvm::json::Value(std::move(function_json)));
  }

  llvm::json::Object root;
  root["schema"] = "obf.audit.v2";
  root["evidence"] = "policy_selection";
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
                      .policy_level = state.report.decision.policy.level,
                      .source_of_truth = ResolveSourceOfTruth(state.report.decision),
                      .decision = &state.report.decision});
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

  const bool changed = std::forward<StageFn>(stage)(module, states, config);
  write_coverage_report(module);
  if (!changed) {
    return coverage_reporting_enabled(module) ? llvm::PreservedAnalyses::none()
                                              : llvm::PreservedAnalyses::all();
  }

  verify_changed_module(module);
  return llvm::PreservedAnalyses::none();
}

template <typename StageFn>
llvm::PreservedAnalyses run_config_stage(llvm::Module& module, StageFn&& stage) {
  const obfuscation_config config = load_active_config();
  validate_effective_config(config, module);
  if (!std::forward<StageFn>(stage)(module, config)) { return llvm::PreservedAnalyses::all(); }

  verify_changed_module(module);
  return llvm::PreservedAnalyses::none();
}

class feature_report_pass : public llvm::PassInfoMixin<feature_report_pass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    const obfuscation_config config = load_active_config();
    llvm::SmallVector<function_pipeline_state, 32> states = build_pipeline_state(module, config);

    for (auto& state : states) {
      if (state.function != nullptr) { state.mba_counts = mba::get_mba_counters(*state.function); }
    }

    llvm::SmallVector<function_report_entry, 32> entries;
    entries.reserve(states.size());
    for (const function_pipeline_state& state : states) { entries.push_back(state.report); }

    const auto predictions = build_prediction_reports(module, states, config);
    const auto observations = build_structural_observation_reports(module, states);
    llvm::outs() << format_feature_report(module.getName(), entries, predictions, observations)
                 << '\n';
    write_coverage_report(module);
    return coverage_reporting_enabled(module) ? llvm::PreservedAnalyses::none()
                                              : llvm::PreservedAnalyses::all();
  }
};

class coverage_start_pass : public llvm::PassInfoMixin<coverage_start_pass> {
 public:
  static bool isRequired() { return true; }
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    start_coverage_reporting(module);
    return llvm::PreservedAnalyses::none();
  }
};

class coverage_report_pass : public llvm::PassInfoMixin<coverage_report_pass> {
 public:
  static bool isRequired() { return true; }
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    llvm::outs() << format_coverage_report(module) << '\n';
    return llvm::PreservedAnalyses::all();
  }
};

class ObfAuditPass : public llvm::PassInfoMixin<ObfAuditPass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    const AuditResolver resolver(module);
    const llvm::SmallVector<AuditRow, 32> rows = resolver.Resolve();

    PrintAuditTable(rows);
    std::string audit_out;
#if !defined(_WIN32)
    audit_out = AuditOutPath.getValue();
#endif
    if (audit_out.empty()) {
      if (const std::optional<std::string> env_audit = get_environment_value("OBF_AUDIT_OUT")) {
        audit_out = *env_audit;
      }
    }
    if (!audit_out.empty()) { WriteAuditJson(audit_out, module.getName(), rows); }

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

class self_checksum_pass : public llvm::PassInfoMixin<self_checksum_pass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    return run_stateful_stage(module,
                              [](llvm::Module& current_module,
                                 const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                 const obfuscation_config& config) {
                                return apply_self_checksum_stage(current_module, states, config);
                              });
  }
};

class indirect_dispatch_pass : public llvm::PassInfoMixin<indirect_dispatch_pass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    return run_stateful_stage(module,
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
    return run_stateful_stage(
        module,
        [](llvm::Module& current_module,
           const llvm::SmallVectorImpl<function_pipeline_state>& states,
           const obfuscation_config& config) {
          const virtualized_function_map virtualized_functions = apply_vm_stage(states, config);
          bool changed = !virtualized_functions.empty();
          changed |= rewrite_calls_to_virtualized_functions(
              current_module, virtualized_functions, effective_vm_mba_depth(config));
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
                                return apply_constant_encoding_stage(
                                    current_module, states, config);
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

class zero_comparison_pass : public llvm::PassInfoMixin<zero_comparison_pass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    return run_stateful_stage(module,
                              [](llvm::Module&,
                                 const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                 const obfuscation_config& config) {
                                return apply_zero_comparison_stage(states, config);
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

bool promote_target_allocas_for_o0(llvm::Function& function,
                                   llvm::FunctionAnalysisManager& fam,
                                   bool normalize_aggregates) {
  llvm::DominatorTree dom_tree(function);
  llvm::AssumptionCache assumption_cache(function);
  llvm::BasicBlock& entry_block = function.getEntryBlock();
  llvm::SmallVector<llvm::AllocaInst*, 8> promotable_allocas;
  bool changed = false;

  while (true) {
    promotable_allocas.clear();
    for (llvm::Instruction& instruction : entry_block) {
      auto* alloca_inst = llvm::dyn_cast<llvm::AllocaInst>(&instruction);
      if (alloca_inst != nullptr && llvm::isAllocaPromotable(alloca_inst)) {
        promotable_allocas.push_back(alloca_inst);
      }
    }

    if (promotable_allocas.empty()) { break; }

    llvm::PromoteMemToReg(promotable_allocas, dom_tree, &assumption_cache);
    changed = true;
  }

  if (changed) { fam.invalidate(function, llvm::PreservedAnalyses::none()); }

  if (normalize_aggregates) {
    // Invoke SROA directly so optnone does not suppress the selected VM
    // preparation. LLVM retains escaping/volatile storage and its memory
    // semantics; VM admission still rejects any allocas that remain.
    const llvm::PreservedAnalyses preserved =
        llvm::SROAPass(llvm::SROAOptions::PreserveCFG).run(function, fam);
    changed |= !preserved.areAllPreserved();
    fam.invalidate(function, preserved);
  }

  return changed;
}

class prepare_o0_pass : public llvm::PassInfoMixin<prepare_o0_pass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager& mam) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);
    llvm::FunctionAnalysisManager& fam =
        mam.getResult<llvm::FunctionAnalysisManagerModuleProxy>(module).getManager();

    // Standard pass instrumentation skips promotion on optnone functions.
    // Prepare selected locals directly without changing optimization or ABI
    // attributes; only VM-eligible functions need aggregate scalar replacement.
    bool changed = false;
    for (const function_pipeline_state& state : states) {
      if (state.report.decision.policy.level == protection_level::none ||
          state.function == nullptr || state.function->isDeclaration() ||
          state.skip_transform_stages) {
        continue;
      }

      changed |= promote_target_allocas_for_o0(
          *state.function, fam, state.report.decision.policy.allow_vm);
    }

    if (!changed) { return llvm::PreservedAnalyses::all(); }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
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

enum class pipeline_route { native, prelink, full_postlink, thin_postlink };

constexpr llvm::StringLiteral kLtoFinalizeGuard = "__obf_lto_finalize_required";

bool is_postlink(pipeline_route route) {
  return route == pipeline_route::full_postlink || route == pipeline_route::thin_postlink;
}

bool has_managed_lto_input_validation() {
  const auto value = get_environment_value("OBF_LTO_INPUTS_VALIDATED");
  return value.has_value() && *value == "1";
}

void require_lto_input_validation(pipeline_route route, const obfuscation_config& config) {
  if (route != pipeline_route::thin_postlink || has_managed_lto_input_validation()) { return; }
  const bool has_required_selectors =
      config.frontend != frontend_kind::generic ||
      std::any_of(config.targets.begin(),
                  config.targets.end(),
                  [](const target_rule& rule) {
                    return rule.level != protection_level::none &&
                           llvm::StringRef(rule.match).find_first_of("*?") == llvm::StringRef::npos;
                  }) ||
      std::any_of(
          config.overrides.begin(), config.overrides.end(), [](const function_override& rule) {
            return rule.level != protection_level::none;
          });
  if (has_required_selectors) {
    llvm::report_fatal_error(
        "ThinLTO configured selectors require whole-input validation by the managed linker route");
  }
}

void validate_direct_full_lto_selectors(llvm::Module& module, const obfuscation_config& config) {
  const auto validate = [&](llvm::StringRef selector, protection_level level) {
    if (level == protection_level::none || selector.find_first_of("*?") != llvm::StringRef::npos ||
        resolve_configured_function(module, selector) != nullptr) {
      return;
    }
    for (const llvm::Function& function : module) {
      if (function.isDeclaration() || !function_has_lto_obligation(function)) { continue; }
      const lto_obligation_record record = read_lto_obligation(function);
      if (record.selector_name == selector &&
          (record.role == lto_obligation_role::protected_entry ||
           record.role == lto_obligation_role::protected_covered ||
           record.role == lto_obligation_role::explicit_none)) {
        return;
      }
    }
    llvm::report_fatal_error(llvm::Twine("unresolved required LTO obfuscation target '") +
                             selector + "'");
  };
  for (const target_rule& rule : config.targets) { validate(rule.match, rule.level); }
  for (const function_override& rule : config.overrides) { validate(rule.name, rule.level); }
}

constexpr llvm::StringLiteral kLtoShapes[] = {"indirectbr", "indirectcall", "atomic", "tokencheck"};

struct lto_shape_counts {
  std::uint64_t values[4] = {};
};

lto_shape_counts count_lto_shapes(const llvm::Function& function) {
  lto_shape_counts counts;
  const llvm::Argument* token =
      function.arg_size() == 0 ? nullptr : function.getArg(function.arg_size() - 1);
  for (const llvm::BasicBlock& block : function) {
    for (const llvm::Instruction& instruction : block) {
      if (llvm::isa<llvm::IndirectBrInst>(instruction)) { ++counts.values[0]; }
      if (const auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction);
          call != nullptr && call->getCalledFunction() == nullptr && !call->isInlineAsm()) {
        ++counts.values[1];
      }
      if (const auto* load = llvm::dyn_cast<llvm::LoadInst>(&instruction);
          load != nullptr && load->isAtomic()) {
        ++counts.values[2];
      }
      if (const auto* store = llvm::dyn_cast<llvm::StoreInst>(&instruction);
          store != nullptr && store->isAtomic()) {
        ++counts.values[2];
      }
      if (const auto* compare = llvm::dyn_cast<llvm::ICmpInst>(&instruction);
          compare != nullptr && token != nullptr &&
          (compare->getOperand(0) == token || compare->getOperand(1) == token)) {
        ++counts.values[3];
      }
    }
  }
  return counts;
}

[[noreturn]] void report_coverage_finalization_failure(llvm::Module& module,
                                                       const llvm::Twine& reason);

void retain_lto_shapes(llvm::Function& function, bool vm_implementation) {
  const lto_shape_counts counts = count_lto_shapes(function);
  if (vm_implementation && counts.values[3] == 0) {
    report_coverage_finalization_failure(
        *function.getParent(), "strong_vm invariant violation: missing VM hidden-token check");
  }
  for (unsigned index = 0; index < std::size(kLtoShapes); ++index) {
    function.addFnAttr((llvm::Twine("obf.lto.shape.") + kLtoShapes[index]).str(),
                       std::to_string(counts.values[index]));
  }
}

void validate_lto_shapes(llvm::Function& function) {
  const lto_shape_counts counts = count_lto_shapes(function);
  for (unsigned index = 0; index < std::size(kLtoShapes); ++index) {
    const llvm::Attribute attribute =
        function.getFnAttribute((llvm::Twine("obf.lto.shape.") + kLtoShapes[index]).str());
    std::uint64_t required = 0;
    if (!attribute.isStringAttribute() || attribute.getValueAsString().getAsInteger(10, required) ||
        counts.values[index] < required) {
      report_coverage_finalization_failure(*function.getParent(),
                                           llvm::Twine("LTO protection structure lost in '") +
                                               function.getName() + "': " + kLtoShapes[index]);
    }
  }
}

llvm::Function& get_lto_finalize_guard(llvm::Module& module) {
  auto* type = llvm::FunctionType::get(llvm::Type::getVoidTy(module.getContext()), false);
  llvm::GlobalValue* existing = module.getNamedValue(kLtoFinalizeGuard);
  auto* guard = llvm::dyn_cast_or_null<llvm::Function>(existing);
  if (existing != nullptr &&
      (guard == nullptr || !guard->isDeclaration() || guard->getFunctionType() != type)) {
    llvm::report_fatal_error("reserved LTO finalization guard must remain an undefined function");
  }
  if (guard == nullptr) {
    guard =
        llvm::Function::Create(type, llvm::GlobalValue::ExternalLinkage, kLtoFinalizeGuard, module);
  }
  guard->setVisibility(llvm::GlobalValue::HiddenVisibility);
  guard->setDSOLocal(true);
  guard->removeFnAttr(llvm::Attribute::NoUnwind);
  guard->removeFnAttr(llvm::Attribute::ReadNone);
  guard->removeFnAttr(llvm::Attribute::ReadOnly);
  guard->removeFnAttr(llvm::Attribute::WillReturn);
  guard->removeFnAttr(llvm::Attribute::Speculatable);
  guard->removeFnAttr(llvm::Attribute::Memory);
  return *guard;
}

void pin_lto_protected_boundary(llvm::Function& function) {
  // The undefined pending call has unknown effects. Do not let stale source
  // memory/progress promises erase it or the hardening surrounding it in LTO.
  for (llvm::Attribute::AttrKind attribute : {llvm::Attribute::MustProgress,
                                              llvm::Attribute::NoFree,
                                              llvm::Attribute::NoRecurse,
                                              llvm::Attribute::NoSync,
                                              llvm::Attribute::WillReturn,
                                              llvm::Attribute::Speculatable}) {
    function.removeFnAttr(attribute);
  }
  function.removeFnAttr(llvm::Attribute::Memory);
  function.removeFnAttr(llvm::Attribute::ReadNone);
  function.removeFnAttr(llvm::Attribute::ReadOnly);
  function.removeFnAttr(llvm::Attribute::AlwaysInline);
  function.removeFnAttr(llvm::Attribute::OptimizeForSize);
  function.removeFnAttr(llvm::Attribute::MinSize);
  function.removeFnAttr(llvm::Attribute::OptimizeForDebugging);
  function.addFnAttr(llvm::Attribute::NoInline);
  function.addFnAttr(llvm::Attribute::OptimizeNone);
}

bool is_retained_native_none_role(lto_obligation_role role) {
  return role == lto_obligation_role::explicit_none || role == lto_obligation_role::raw_none;
}

bool function_has_pending_lto_finalize_guard(const llvm::Function& function,
                                             const llvm::Function& guard) {
  for (const llvm::BasicBlock& block : function) {
    for (const llvm::Instruction& instruction : block) {
      const auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction);
      if (call != nullptr && call->getCalledFunction() == &guard && call->arg_size() == 0) {
        return true;
      }
    }
  }

  return false;
}

// A postlink orchestrator promotion revives a prelink-retained native body.
// Re-emit the raw-entry contract so later post-VM state rebuilds keep the
// function active and the finalizer guard now covers the promoted boundary.

bool prepare_retained_native_orchestrator_promotions(
    llvm::Module& module,
    llvm::SmallVectorImpl<function_pipeline_state>& states,
    llvm::FunctionAnalysisManager& fam) {
  llvm::Function* guard = nullptr;
  bool changed = false;
  for (function_pipeline_state& state : states) {
    llvm::Function* function = state.function;
    if (function == nullptr || function->isDeclaration() || !state.lto.present ||
        !is_retained_native_none_role(state.lto.role) ||
        state.report.decision.policy.level == protection_level::none) {
      continue;
    }

    pin_lto_protected_boundary(*function);

    lto_obligation_record record = state.lto;
    record.role = lto_obligation_role::raw_entry;
    record.source = state.report.decision.source;
    record.policy = state.report.decision.policy;
    record.selection_detail = state.report.decision.detail;
    record.requires_finalization = true;
    record.pinned_noinline = true;

    clear_lto_obligation(*function);
    apply_lto_obligation(*function, record);

    if (guard == nullptr) { guard = &get_lto_finalize_guard(module); }
    if (!function_has_pending_lto_finalize_guard(*function, *guard)) {
      llvm::IRBuilder<> builder(&*function->getEntryBlock().getFirstInsertionPt());
      builder.CreateCall(guard);
    }

    fam.invalidate(*function, llvm::PreservedAnalyses::none());

    state.lto = record;
    state.skip_transform_stages = false;
    changed = true;
  }

  return changed;
}

struct retained_function_contract {
  llvm::Function* function = nullptr;
  lto_obligation_record record;
  bool vm_implementation = false;
};

std::vector<retained_function_contract>
capture_lto_contracts(llvm::Module& module,
                      const llvm::SmallVectorImpl<function_pipeline_state>& states,
                      const virtualized_function_map& bindings,
                      const obfuscation_config& config) {
  std::vector<retained_function_contract> contracts;
  const std::uint64_t config_identity = compute_lto_config_identity(config);
  llvm::SmallPtrSet<llvm::Function*, 32> original_functions;
  llvm::DenseMap<llvm::Function*, std::size_t> contract_indices;
  for (const function_pipeline_state& state : states) {
    if (state.function == nullptr || state.function->isDeclaration()) { continue; }
    original_functions.insert(state.function);
    if (state.lto.present) { continue; }
    const bool excluded = state.report.decision.policy.level == protection_level::none &&
                          (state.report.decision.source == policy_source::source_annotation ||
                           state.report.decision.source == policy_source::explicit_override ||
                           state.report.decision.source == policy_source::config_rule);
    const bool internal = state.report.decision.detail == "runtime internal forced none";
    if (state.report.decision.policy.level == protection_level::none && !excluded && !internal) {
      continue;
    }
    lto_obligation_record record;
    record.present = true;
    record.role = excluded   ? lto_obligation_role::explicit_none
                  : internal ? lto_obligation_role::generated_internal
                             : lto_obligation_role::protected_entry;
    record.selector_name = state.report.features.name;
    record.selection_detail = state.report.decision.detail;
    record.annotation = state.report.annotation;
    record.source = state.report.decision.source;
    record.policy = state.report.decision.policy;
    record.config_identity = config_identity;
    record.decision_seed = state.report.decision.seed;
    record.entry_identity = stable_hash_string(record.selector_name, record.decision_seed);
    record.requires_finalization = !excluded && !internal;
    contract_indices[state.function] = contracts.size();
    contracts.push_back({state.function, std::move(record), false});
  }
  for (const auto& entry : bindings) {
    const virtualized_function_binding& binding = entry.second;
    if (binding.state == nullptr || binding.interface_function == nullptr) { continue; }
    lto_obligation_record record;
    record.present = true;
    record.role = lto_obligation_role::protected_entry;
    record.selector_name = binding.state->report.features.name;
    record.annotation = binding.state->report.annotation;
    record.selection_detail = binding.state->report.decision.detail;
    record.source = binding.state->report.decision.source;
    record.policy = binding.state->report.decision.policy;
    record.config_identity = config_identity;
    record.decision_seed = binding.state->report.decision.seed;
    record.entry_identity =
        stable_hash_string(binding.interface_function->getName(), record.decision_seed);
    record.requires_finalization = true;
    record.uses_target_cache = binding.uses_target_cache;
    record.uses_shared_seed_resolver = binding.uses_shared_seed_resolver;
    const auto existing = contract_indices.find(binding.interface_function);
    if (existing != contract_indices.end()) {
      contracts[existing->second].record = record;
    } else {
      contract_indices[binding.interface_function] = contracts.size();
      contracts.push_back({binding.interface_function, record, false});
      if (const auto owner = contract_indices.find(binding.state->function);
          owner != contract_indices.end()) {
        contracts[owner->second].record.role = lto_obligation_role::protected_covered;
      }
    }
    record.role = lto_obligation_role::vm_implementation;
    contract_indices[binding.implementation_function] = contracts.size();
    contracts.push_back({binding.implementation_function, record, true});
    record.role = lto_obligation_role::vm_entry_thunk;
    contract_indices[binding.entry_thunk_function] = contracts.size();
    contracts.push_back({binding.entry_thunk_function, record, false});
  }
  for (llvm::Function& function : module) {
    if (function.isDeclaration() || function_has_lto_obligation(function) ||
        original_functions.contains(&function)) {
      continue;
    }
    if (contract_indices.contains(&function)) { continue; }
    lto_obligation_record record;
    record.present = true;
    record.role = lto_obligation_role::generated_internal;
    record.config_identity = config_identity;
    if (const auto owner = read_string_protection_owner(function)) {
      record.policy = make_function_policy(owner->level);
      record.decision_seed = owner->seed;
    }
    contracts.push_back({&function, std::move(record), false});
  }
  return contracts;
}

void retain_lto_contracts(llvm::Module& module,
                          std::vector<retained_function_contract>& contracts) {
  llvm::Function* guard = nullptr;
  for (retained_function_contract& contract : contracts) {
    llvm::Function* function = contract.function;
    if (function == nullptr || function->isDeclaration()) { continue; }
    if (contract.record.role == lto_obligation_role::generated_internal) {
      contract.record.pinned_noinline = function->hasFnAttribute(llvm::Attribute::NoInline) &&
                                        function->hasFnAttribute(llvm::Attribute::OptimizeNone);
      if (contract.record.pinned_noinline) { retain_lto_shapes(*function, false); }
    } else if (contract.record.role != lto_obligation_role::explicit_none) {
      pin_lto_protected_boundary(*function);
      contract.record.pinned_noinline = true;
      retain_lto_shapes(*function, contract.vm_implementation);
    }
    apply_lto_obligation(*function, contract.record);
    if (!contract.record.requires_finalization) { continue; }
    if (guard == nullptr) { guard = &get_lto_finalize_guard(module); }
    llvm::IRBuilder<> builder(&*function->getEntryBlock().getFirstInsertionPt());
    builder.CreateCall(guard);
  }
}

[[noreturn]] void report_coverage_finalization_failure(llvm::Module& module,
                                                       const llvm::Twine& reason) {
  if (coverage_reporting_enabled(module)) {
    record_coverage_event(module,
                          "finalization",
                          "lto_contracts",
                          "",
                          module.getName(),
                          "rejected",
                          reason.str(),
                          0,
                          "module");
    write_coverage_report(module);
  }
  llvm::report_fatal_error(reason);
}

virtualized_function_map
recover_lto_bindings(const llvm::SmallVectorImpl<function_pipeline_state>& states) {
  struct retained_vm_roles {
    const function_pipeline_state* implementation = nullptr;
    const function_pipeline_state* thunk = nullptr;
    const function_pipeline_state* interface = nullptr;
  };
  llvm::DenseMap<std::uint64_t, retained_vm_roles> roles;
  llvm::DenseMap<std::uint64_t, const function_pipeline_state*> covered_owners;
  virtualized_function_map bindings;
  for (const function_pipeline_state& state : states) {
    if (state.function == nullptr || state.function->isDeclaration() || !state.lto.present) {
      continue;
    }
    if (state.lto.role == lto_obligation_role::raw_entry ||
        state.lto.role == lto_obligation_role::raw_none) {
      continue;
    }
    if (state.lto.role != lto_obligation_role::explicit_none &&
        (state.lto.role != lto_obligation_role::generated_internal || state.lto.pinned_noinline)) {
      if (!state.function->hasFnAttribute(llvm::Attribute::NoInline) ||
          !state.function->hasFnAttribute(llvm::Attribute::OptimizeNone)) {
        report_coverage_finalization_failure(
            *state.function->getParent(),
            "LTO protection structure lost: unpinned protected boundary");
      }
      validate_lto_shapes(*state.function);
      // Re-establish the encoded boundary's conservative optimizer contract
      // without touching source ABI, semantic, sanitizer, or subtarget attrs.
      pin_lto_protected_boundary(*state.function);
    }
    if (state.lto.role == lto_obligation_role::vm_implementation ||
        state.lto.role == lto_obligation_role::vm_entry_thunk) {
      // A rewritten caller can keep the thunk/implementation live after the
      // original interface is discarded. Validate those live roles directly;
      // do not require an artificial used-list reference to a dead wrapper.
      if (state.lto.policy.level == protection_level::strong_vm) {
        const lto_shape_counts shapes = count_lto_shapes(*state.function);
        const bool is_implementation = state.lto.role == lto_obligation_role::vm_implementation;
        const bool hidden_token_valid =
            state.function->arg_size() != 0 &&
            state.function->getArg(state.function->arg_size() - 1)->getType()->isIntegerTy(64);
        if (!state.function->hasLocalLinkage() || !hidden_token_valid ||
            state.lto.uses_target_cache || state.lto.uses_shared_seed_resolver ||
            shapes.values[2] != 0 ||
            (is_implementation ? shapes.values[3] == 0 : shapes.values[1] == 0)) {
          report_coverage_finalization_failure(
              *state.function->getParent(),
              "strong_vm invariant violation: live retained VM role lost protection");
        }
      }
      retained_vm_roles& group = roles[state.lto.entry_identity];
      const function_pipeline_state*& slot =
          state.lto.role == lto_obligation_role::vm_implementation ? group.implementation
                                                                   : group.thunk;
      if (slot != nullptr) {
        report_coverage_finalization_failure(
            *state.function->getParent(),
            "LTO protection structure lost: duplicate retained VM role");
      }
      slot = &state;
    }
    if (state.lto.role == lto_obligation_role::protected_covered) {
      const std::uint64_t owner_identity =
          stable_hash_string(state.lto.selector_name, state.lto.decision_seed);
      if (!covered_owners.try_emplace(owner_identity, &state).second) {
        report_coverage_finalization_failure(
            *state.function->getParent(),
            "LTO protection structure lost: duplicate retained VM owner");
      }
    }
    if (state.lto.role == lto_obligation_role::protected_entry) {
      retained_vm_roles& group = roles[state.lto.entry_identity];
      if (group.interface != nullptr) {
        report_coverage_finalization_failure(
            *state.function->getParent(),
            "LTO protection structure lost: duplicate retained VM interface");
      }
      group.interface = &state;
    }
  }
  for (const auto& entry : roles) {
    const retained_vm_roles& group = entry.second;
    if (group.implementation == nullptr && group.thunk == nullptr) { continue; }
    if (group.implementation == nullptr || group.thunk == nullptr) {
      const auto* live = group.implementation != nullptr ? group.implementation : group.thunk;
      report_coverage_finalization_failure(
          *live->function->getParent(),
          "LTO protection structure lost: incomplete retained VM boundary");
    }
    const function_pipeline_state& representative = *group.implementation;
    virtualized_function_binding binding;
    binding.interface_function = group.interface == nullptr ? nullptr : group.interface->function;
    binding.implementation_function = group.implementation->function;
    binding.entry_thunk_function = group.thunk->function;
    binding.state = group.interface;
    binding.uses_target_cache = representative.lto.uses_target_cache;
    binding.uses_shared_seed_resolver = representative.lto.uses_shared_seed_resolver;
    for (const function_pipeline_state* candidate : {group.interface, group.thunk}) {
      if (candidate == nullptr) { continue; }
      if (candidate->lto.selector_name != representative.lto.selector_name ||
          candidate->lto.decision_seed != representative.lto.decision_seed) {
        report_coverage_finalization_failure(
            *candidate->function->getParent(),
            "LTO protection structure lost: inconsistent retained VM identity");
      }
    }
    const std::uint64_t owner_identity =
        stable_hash_string(representative.lto.selector_name, representative.lto.decision_seed);
    if (const auto owner = covered_owners.find(owner_identity); owner != covered_owners.end()) {
      if (owner->second->lto.selector_name != representative.lto.selector_name ||
          owner->second->lto.decision_seed != representative.lto.decision_seed) {
        report_coverage_finalization_failure(
            *representative.function->getParent(),
            "LTO protection structure lost: inconsistent retained VM owner");
      }
      binding.state = owner->second;
    }
    const llvm::Function& implementation = *binding.implementation_function;
    const llvm::Function& thunk = *binding.entry_thunk_function;
    bool boundary_valid =
        implementation.arg_size() != 0 &&
        implementation.getArg(implementation.arg_size() - 1)->getType()->isIntegerTy(64) &&
        thunk.getFunctionType() == implementation.getFunctionType() &&
        thunk.getCallingConv() == implementation.getCallingConv();
    if (binding.interface_function != nullptr) {
      const llvm::Function& interface = *binding.interface_function;
      boundary_valid &= implementation.arg_size() == interface.arg_size() + 1 &&
                        implementation.getReturnType() == interface.getReturnType() &&
                        implementation.getCallingConv() == interface.getCallingConv();
      if (boundary_valid) {
        for (unsigned index = 0; index < interface.arg_size(); ++index) {
          boundary_valid &=
              interface.getArg(index)->getType() == implementation.getArg(index)->getType();
        }
      }
    }
    if (!boundary_valid) {
      report_coverage_finalization_failure(
          *representative.function->getParent(),
          "LTO protection structure lost: retained VM ABI/token mismatch");
    }
    if (representative.lto.policy.level == protection_level::strong_vm) {
      const lto_shape_counts implementation_shapes = count_lto_shapes(implementation);
      const lto_shape_counts thunk_shapes = count_lto_shapes(thunk);
      bool forwarding_valid = thunk_shapes.values[1] != 0 && implementation_shapes.values[3] != 0 &&
                              implementation_shapes.values[2] == 0 && thunk_shapes.values[2] == 0;
      if (binding.interface_function != nullptr) {
        const lto_shape_counts interface_shapes = count_lto_shapes(*binding.interface_function);
        forwarding_valid &= interface_shapes.values[1] != 0 && interface_shapes.values[2] == 0;
      }
      if (!forwarding_valid) {
        report_coverage_finalization_failure(*representative.function->getParent(),
                                             "strong_vm invariant violation: retained encoded "
                                             "forwarding/token/no-cache boundary lost");
      }
    }
    // A dead source interface does not invalidate live regional owner coverage.
    // Completely orphaned implementation/thunk roles were checked above, but
    // there is no live source state for the source-coverage gates in that case.
    if (binding.state != nullptr) { bindings[implementation.getName()] = std::move(binding); }
  }
  return bindings;
}

bool release_lto_contracts(llvm::Module& module) {
  llvm::Function* guard = module.getFunction(kLtoFinalizeGuard);
  llvm::SmallVector<llvm::CallInst*, 32> calls;
  llvm::SmallPtrSet<llvm::Function*, 32> guarded_functions;
  if (guard != nullptr) {
    if (!guard->isDeclaration() || guard->getVisibility() != llvm::GlobalValue::HiddenVisibility) {
      report_coverage_finalization_failure(
          module, "LTO finalization guard must remain undefined and hidden until release");
    }
    for (llvm::User* user : guard->users()) {
      auto* call = llvm::dyn_cast<llvm::CallInst>(user);
      if (call == nullptr || call->getCalledFunction() != guard || call->arg_size() != 0) {
        report_coverage_finalization_failure(module, "invalid pending LTO finalization guard use");
      }
      const lto_obligation_record record = read_lto_obligation(*call->getFunction());
      if (!record.present || !record.requires_finalization) {
        report_coverage_finalization_failure(
            module, "pending LTO finalization guard has no retained obligation");
      }
      calls.push_back(call);
      guarded_functions.insert(call->getFunction());
    }
  }
  bool changed = guard != nullptr;
  for (llvm::Function& function : module) {
    const lto_obligation_record record = read_lto_obligation(function);
    if (!record.present) { continue; }
    if (!function.isDeclaration() && record.requires_finalization) {
      if (!guarded_functions.contains(&function)) {
        report_coverage_finalization_failure(
            module,
            llvm::Twine("missing pending LTO finalization guard in '") + function.getName() + "'");
      }
    }
    clear_lto_obligation(function);
    changed = true;
  }
  for (llvm::CallInst* call : calls) { call->eraseFromParent(); }
  if (guard != nullptr) { guard->eraseFromParent(); }
  return changed;
}

class capture_lto_selection_pass : public llvm::PassInfoMixin<capture_lto_selection_pass> {
 public:
  explicit capture_lto_selection_pass(pipeline_route route) : route_(route) {}
  static bool isRequired() { return true; }

  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
    const obfuscation_config config = load_active_config();
    require_lto_input_validation(route_, config);
    if (route_ == pipeline_route::full_postlink && !has_managed_lto_input_validation()) {
      validate_direct_full_lto_selectors(module, config);
    }
    const auto states =
        build_lto_pipeline_state(module, config, has_managed_lto_input_validation());
    const std::uint64_t config_identity = compute_lto_config_identity(config);
    bool changed = false;
    for (const function_pipeline_state& state : states) {
      llvm::Function* function = state.function;
      if (function == nullptr || function->isDeclaration() || state.lto.present) { continue; }
      const bool excluded = state.report.decision.policy.level == protection_level::none &&
                            (state.report.decision.source == policy_source::source_annotation ||
                             state.report.decision.source == policy_source::explicit_override ||
                             state.report.decision.source == policy_source::config_rule);
      if (state.report.decision.policy.level == protection_level::none && !excluded) { continue; }
      lto_obligation_record record;
      record.present = true;
      record.role = excluded ? lto_obligation_role::raw_none : lto_obligation_role::raw_entry;
      record.selector_name = state.report.features.name;
      record.annotation = state.report.annotation;
      record.selection_detail = state.report.decision.detail;
      record.source = state.report.decision.source;
      record.policy = state.report.decision.policy;
      record.config_identity = config_identity;
      record.decision_seed = state.report.decision.seed;
      record.entry_identity = stable_hash_string(record.selector_name, record.decision_seed);
      if (!excluded) { pin_lto_protected_boundary(*function); }
      apply_lto_obligation(*function, record);
      changed = true;
    }
    if (!changed) { return llvm::PreservedAnalyses::all(); }
    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }

 private:
  pipeline_route route_;
};

class safe_pipeline_pass : public llvm::PassInfoMixin<safe_pipeline_pass> {
 public:
  explicit safe_pipeline_pass(pipeline_route route = pipeline_route::native) : route_(route) {}

  static bool isRequired() { return true; }

  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager& mam) {
    const obfuscation_config config = load_active_config();
    require_lto_input_validation(route_, config);
    const bool allow_unresolved = route_ == pipeline_route::prelink ||
                                  (is_postlink(route_) && has_managed_lto_input_validation());
    llvm::SmallVector<function_pipeline_state, 32> states =
        build_lto_pipeline_state(module, config, allow_unresolved);
    bool changed = false;
    if (is_postlink(route_)) {
      llvm::FunctionAnalysisManager& fam =
          mam.getResult<llvm::FunctionAnalysisManagerModuleProxy>(module).getManager();
      changed |= prepare_retained_native_orchestrator_promotions(module, states, fam);
      // The backend may receive raw optnone IR; use the same targeted scalar
      // preparation as native O0 without changing VM admission or budgets.
      for (const function_pipeline_state& state : states) {
        if (state.function != nullptr && !state.function->isDeclaration() &&
            !state.skip_transform_stages &&
            state.report.decision.policy.level != protection_level::none) {
          changed |= promote_target_allocas_for_o0(
              *state.function, fam, state.report.decision.policy.allow_vm);
        }
      }
    }
    virtualized_function_map retained_bindings;
    if (is_postlink(route_)) { retained_bindings = recover_lto_bindings(states); }
    const bool has_fresh_target = std::any_of(states.begin(), states.end(), [](const auto& state) {
      return state.function != nullptr && !state.function->isDeclaration() &&
             !state.skip_transform_stages &&
             state.report.decision.policy.level != protection_level::none;
    });
    if (!is_postlink(route_) || has_fresh_target) {
      changed |= apply_entropy_initialization_stage(module, get_obf_seed_override());
    }

    constexpr protection_level vm_level = protection_level::vm;
    const virtualized_function_map vm_only = apply_vm_stage(states, config, &vm_level);
    changed |= !vm_only.empty();
    changed |=
        rewrite_calls_to_virtualized_functions(module, vm_only, effective_vm_mba_depth(config));

    constexpr protection_level strong_vm_level = protection_level::strong_vm;
    const std::size_t selected_strong_vm_count =
        count_states_at_level(states, protection_level::strong_vm);
    emit_progress_warning_if_enabled(
        config, "starting strong_vm lowering", selected_strong_vm_count);
    const virtualized_function_map strong_vm_virtualized =
        apply_vm_stage(states, config, &strong_vm_level);
    changed |= !strong_vm_virtualized.empty();
    changed |= rewrite_calls_to_virtualized_functions(
        module, strong_vm_virtualized, effective_vm_mba_depth(config));

    virtualized_function_map post_vm_virtualized = vm_only;
    for (const auto& entry : strong_vm_virtualized) {
      post_vm_virtualized[entry.getKey()] = entry.second;
    }

    const llvm::SmallVector<function_pipeline_state, 32> post_vm_states =
        build_lto_pipeline_state(module, config, allow_unresolved);

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
    // Flatten first so strong-pipeline eligibility still reflects the optimized
    // source CFG, snapshot the original source operators before later stages
    // synthesize their own compares and literals, then substitute those saved
    // sites after zero-comparison and constant encoding spend their quotas.
    const llvm::StringSet<> flattened_functions =
        apply_control_flattening_stage(post_vm_states, config, &all_vm_virtualized);
    changed |= !flattened_functions.empty();
    const instruction_substitution_stage_candidates substitution_candidates =
        snapshot_instruction_substitution_stage_candidates(
            post_vm_states, config, &all_vm_virtualized);
    changed |= apply_zero_comparison_stage(post_vm_states, config, &all_vm_virtualized);
    changed |= apply_constant_encoding_stage(module, post_vm_states, config, &all_vm_virtualized);
    changed |= apply_instruction_substitution_stage(
        post_vm_states, config, substitution_candidates, &all_vm_virtualized);
    changed |= apply_opaque_gep_stage(post_vm_states, config, &all_vm_virtualized);
    changed |= apply_opaque_predicate_stage(post_vm_states, config, &all_vm_virtualized);
    changed |= apply_function_outlining_stage(post_vm_states, config, &all_vm_virtualized);
    changed |= apply_bogus_control_flow_stage(post_vm_states, config, &all_vm_virtualized);
    changed |= apply_self_checksum_stage(module, post_vm_states, config);

    llvm::StringSet<> block_split_skips;
    for (const auto& entry : all_vm_virtualized) { block_split_skips.insert(entry.getKey()); }
    for (const auto& entry : flattened_functions) { block_split_skips.insert(entry.getKey()); }
    changed |= apply_block_split_stage(post_vm_states, config, &block_split_skips);

    emit_progress_warning_if_enabled(
        config, "starting strong_vm hardening", strong_vm_virtualized.size());
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
    virtualized_function_map validation_bindings = retained_bindings;
    for (const auto& entry : post_vm_virtualized) {
      validation_bindings[entry.getKey()] = entry.second;
    }
    if (coverage_reporting_enabled(module)) {
      record_coverage_event(module,
                            "finalization",
                            "security_gates",
                            "",
                            module.getName(),
                            "started",
                            "compiler validation started",
                            0,
                            "module");
      write_coverage_report(module);
    }
    changed |= enforce_security_gates(module, states, validation_bindings, config);
    record_coverage_event(module,
                          "finalization",
                          "security_gates",
                          "",
                          module.getName(),
                          "validated",
                          "compiler security gates passed",
                          0,
                          "module");
    std::vector<retained_function_contract> contracts;
    if (route_ == pipeline_route::prelink) {
      contracts = capture_lto_contracts(module, states, post_vm_virtualized, config);
    }
    // Validate live retained protections and LLVM IR before releasing the
    // side-effecting undefined guard. No backend can silently bypass a gate.
    if (is_postlink(route_)) {
      verify_changed_module(module);
      changed |= release_lto_contracts(module);
      record_coverage_event(module,
                            "finalization",
                            "lto_contracts",
                            "",
                            module.getName(),
                            "validated",
                            "retained obligations validated and guards released",
                            0,
                            "module");
    }
    if (!is_postlink(route_) || has_fresh_target) {
      changed |= apply_artifact_cleanup_stage(module, config);
    }
    if (route_ == pipeline_route::prelink) {
      retain_lto_contracts(module, contracts);
      changed |= !contracts.empty();
      record_coverage_event(module,
                            "finalization",
                            "lto_contracts",
                            "",
                            module.getName(),
                            "pending",
                            "backend finalization required",
                            contracts.size(),
                            "module");
    }

    if (!changed && !coverage_reporting_enabled(module)) { return llvm::PreservedAnalyses::all(); }

    verify_changed_module(module);
    record_coverage_event(module,
                          "finalization",
                          "compiler_pipeline",
                          "",
                          module.getName(),
                          route_ == pipeline_route::prelink ? "pending" : "completed",
                          route_ == pipeline_route::prelink ? "backend finalization required"
                                                            : "compiler pipeline and IR validated",
                          0,
                          "module");
    write_coverage_report(module);
    return llvm::PreservedAnalyses::none();
  }

 private:
  pipeline_route route_;
};

}  // namespace

}  // namespace obf

extern "C" OBF_PLUGIN_EXPORT ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "obf_plugin", "0.1", [](llvm::PassBuilder& pass_builder) {
            pass_builder.registerPipelineParsingCallback(
                [](llvm::StringRef name,
                   llvm::ModulePassManager& module_pm,
                   llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
                  if (name == "obf-feature-report") {
                    module_pm.addPass(obf::feature_report_pass());
                    return true;
                  }

                  if (name == "obf-coverage-start") {
                    module_pm.addPass(obf::coverage_start_pass());
                    return true;
                  }
                  if (name == "obf-coverage-report") {
                    module_pm.addPass(obf::coverage_report_pass());
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

                  if (name == "obf-self-checksum") {
                    module_pm.addPass(obf::self_checksum_pass());
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

                  if (name == "obf-zero-comparison") {
                    module_pm.addPass(obf::zero_comparison_pass());
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

                  if (name == "obf-prepare-o0") {
                    module_pm.addPass(obf::prepare_o0_pass());
                    return true;
                  }

                  if (name == "obf-safe-pipeline") {
                    module_pm.addPass(obf::safe_pipeline_pass());
                    return true;
                  }

                  if (name == "obf-lto-finalize") {
                    module_pm.addPass(obf::safe_pipeline_pass(obf::pipeline_route::thin_postlink));
                    return true;
                  }

                  return false;
                });

            pass_builder.registerFullLinkTimeOptimizationEarlyEPCallback(
                [](llvm::ModulePassManager& module_pm, llvm::OptimizationLevel) {
                  if (!obf::is_obfuscation_enabled()) { return; }
                  module_pm.addPass(
                      obf::capture_lto_selection_pass(obf::pipeline_route::full_postlink));
                });
            pass_builder.registerPipelineEarlySimplificationEPCallback(
                [](llvm::ModulePassManager& module_pm,
                   llvm::OptimizationLevel,
                   llvm::ThinOrFullLTOPhase phase) {
                  if (!obf::is_obfuscation_enabled() ||
                      phase != llvm::ThinOrFullLTOPhase::ThinLTOPostLink) {
                    return;
                  }
                  module_pm.addPass(
                      obf::capture_lto_selection_pass(obf::pipeline_route::thin_postlink));
                });

            pass_builder.registerOptimizerLastEPCallback([](llvm::ModulePassManager& module_pm,
                                                            llvm::OptimizationLevel level,
                                                            llvm::ThinOrFullLTOPhase phase) {
              if (!obf::is_obfuscation_enabled()) { return; }
              if (phase == llvm::ThinOrFullLTOPhase::ThinLTOPostLink) {
                module_pm.addPass(obf::safe_pipeline_pass(obf::pipeline_route::thin_postlink));
              } else if (level != llvm::OptimizationLevel::O0 &&
                         (phase == llvm::ThinOrFullLTOPhase::ThinLTOPreLink ||
                          phase == llvm::ThinOrFullLTOPhase::FullLTOPreLink)) {
                module_pm.addPass(obf::safe_pipeline_pass(obf::pipeline_route::prelink));
              } else if (level != llvm::OptimizationLevel::O0 &&
                         phase == llvm::ThinOrFullLTOPhase::None) {
                module_pm.addPass(obf::safe_pipeline_pass());
              }
            });

            pass_builder.registerFullLinkTimeOptimizationLastEPCallback(
                [](llvm::ModulePassManager& module_pm, llvm::OptimizationLevel level) {
                  if (!obf::is_obfuscation_enabled()) { return; }
                  module_pm.addPass(obf::safe_pipeline_pass(obf::pipeline_route::full_postlink));
                });

            pass_builder.registerPipelineStartEPCallback(
                [](llvm::ModulePassManager& module_pm, llvm::OptimizationLevel level) {
                  if (!obf::is_obfuscation_enabled()) { return; }
                  if (level == llvm::OptimizationLevel::O0) {
                    module_pm.addPass(obf::prepare_o0_pass());
                    // LLVM22 does not pass the phase to PipelineStart and only
                    // invokes it in frontend pipelines. The wrapper supplies
                    // the effective LTO compile mode, including -O0.
                    const obf::pipeline_route route =
                        obf::get_active_lto_mode() == obf::obf_lto_mode::none
                            ? obf::pipeline_route::native
                            : obf::pipeline_route::prelink;
                    module_pm.addPass(obf::safe_pipeline_pass(route));
                  }
                });
          }};
}
