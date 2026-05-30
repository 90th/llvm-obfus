#include "obf/plugin/obfuscator_plugin_internal.h"

#include "obf/vm/candidate_analysis.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"

#include <optional>
#include <string>
#include <vector>

namespace obf {

namespace {

transform_report_entry make_transform_report(llvm::StringRef pass,
                                             llvm::StringRef target_kind,
                                             llvm::StringRef target_name,
                                             bool applied,
                                             llvm::StringRef detail,
                                             std::size_t count) {
  return {.pass = pass.str(),
          .target_kind = target_kind.str(),
          .target_name = target_name.str(),
          .status = applied ? "applied" : "skipped",
          .detail = detail.str(),
          .count = count};
}

}  // namespace

llvm::SmallVector<transform_report_entry, 64>
build_transform_reports(llvm::Module& module,
                        const llvm::SmallVectorImpl<function_pipeline_state>& states,
                        const obfuscation_config& config) {
  llvm::SmallVector<transform_report_entry, 64> reports;
  llvm::StringSet<> virtualized_functions;

  for (const function_pipeline_state& state : states) {
    if (state.function == nullptr || !state.report.decision.policy.allow_vm) { continue; }

    if (vm::analyze_candidate(*state.function).eligible) {
      virtualized_functions.insert(state.function->getName());
    }
  }

  for (const function_pipeline_state& state : states) {
    const llvm::Function* function = state.function;
    if (function == nullptr) { continue; }

    const bool suppressed_by_vm = virtualized_functions.contains(function->getName()) &&
                                  state.report.decision.policy.level != protection_level::strong_vm;
    const bool deferred_to_vm_hardening =
        virtualized_functions.contains(function->getName()) &&
        state.report.decision.policy.level == protection_level::strong_vm;

    const vm::candidate_result vm_result = vm::analyze_candidate(*function);
    if (!state.report.decision.policy.allow_vm) {
      reports.push_back(
          make_transform_report("vm",
                                "function",
                                function->getName(),
                                false,
                                function->isDeclaration() ? "declaration" : "policy disallows vm",
                                0));
    } else {
      reports.push_back(
          make_transform_report("vm",
                                "function",
                                function->getName(),
                                vm_result.eligible,
                                vm_result.detail,
                                vm_result.eligible ? vm_result.instruction_count : 0));
    }

    if (suppressed_by_vm) {
      reports.push_back(make_transform_report(
          "block_split", "function", function->getName(), false, "suppressed after vm", 0));
    } else if (!state.report.decision.policy.allow_split) {
      reports.push_back(make_transform_report("block_split",
                                              "function",
                                              function->getName(),
                                              false,
                                              function->isDeclaration() ? "declaration"
                                                                        : "policy disallows split",
                                              0));
    } else {
      const block_split_options options = build_block_split_options(config, state.report.decision);
      const block_split_result result =
          analyze_block_split(*function, options, state.report.decision.seed);
      reports.push_back(make_transform_report("block_split",
                                              "function",
                                              function->getName(),
                                              result.split_count > 0,
                                              result.detail,
                                              result.split_count));
    }

    if (suppressed_by_vm) {
      reports.push_back(make_transform_report(
          "constant_encoding", "function", function->getName(), false, "suppressed after vm", 0));
    } else if (!state.report.decision.policy.allow_constant_encoding) {
      reports.push_back(make_transform_report(
          "constant_encoding",
          "function",
          function->getName(),
          false,
          function->isDeclaration() ? "declaration" : "policy disallows constant encoding",
          0));
    } else {
      const constant_encoding_options options =
          build_constant_encoding_options(config, state.report.decision);
      const constant_encoding_result result =
          analyze_constant_encoding(*function, options, state.report.decision.seed);
      reports.push_back(make_transform_report("constant_encoding",
                                              "function",
                                              function->getName(),
                                              result.encoded_count > 0,
                                              result.detail,
                                              result.encoded_count));
    }

    if (suppressed_by_vm) {
      reports.push_back(make_transform_report("instruction_substitution",
                                              "function",
                                              function->getName(),
                                              false,
                                              "suppressed after vm",
                                              0));
    } else if (deferred_to_vm_hardening) {
      reports.push_back(make_transform_report("instruction_substitution",
                                              "function",
                                              function->getName(),
                                              false,
                                              "deferred to vm hardening",
                                              0));
    } else if (!state.report.decision.policy.allow_instruction_substitution) {
      reports.push_back(make_transform_report(
          "instruction_substitution",
          "function",
          function->getName(),
          false,
          function->isDeclaration() ? "declaration" : "policy disallows instruction substitution",
          0));
    } else {
      const instruction_substitution_options options =
          build_instruction_substitution_options(config, state.report.decision);
      const instruction_substitution_result result =
          analyze_instruction_substitution(*function, options);
      reports.push_back(make_transform_report("instruction_substitution",
                                              "function",
                                              function->getName(),
                                              result.substitution_count > 0,
                                              result.detail,
                                              result.substitution_count));
    }

    if (suppressed_by_vm) {
      reports.push_back(make_transform_report(
          "control_flattening", "function", function->getName(), false, "suppressed after vm", 0));
    } else if (deferred_to_vm_hardening) {
      reports.push_back(make_transform_report("control_flattening",
                                              "function",
                                              function->getName(),
                                              false,
                                              "deferred to vm hardening",
                                              0));
    } else if (!state.report.decision.policy.allow_flattening) {
      reports.push_back(make_transform_report(
          "control_flattening",
          "function",
          function->getName(),
          false,
          function->isDeclaration() ? "declaration" : "policy disallows flattening",
          0));
    } else {
      const control_flattening_options options =
          build_control_flattening_options(config, state.report.decision);
      const control_flattening_result result = analyze_control_flattening(*function, options);
      reports.push_back(make_transform_report("control_flattening",
                                              "function",
                                              function->getName(),
                                              result.flattened,
                                              result.detail,
                                              result.state_count));
    }

    if (suppressed_by_vm) {
      reports.push_back(make_transform_report(
          "function_outlining", "function", function->getName(), false, "suppressed after vm", 0));
    } else if (deferred_to_vm_hardening) {
      reports.push_back(make_transform_report("function_outlining",
                                              "function",
                                              function->getName(),
                                              false,
                                              "deferred to vm hardening",
                                              0));
    } else if (!state.report.decision.policy.allow_function_outlining) {
      reports.push_back(make_transform_report(
          "function_outlining",
          "function",
          function->getName(),
          false,
          function->isDeclaration() ? "declaration" : "policy disallows function outlining",
          0));
    } else {
      const function_outlining_options options =
          build_function_outlining_options(config, state.report.decision);
      const function_outlining_result result = analyze_function_outlining(*function, options);
      reports.push_back(make_transform_report("function_outlining",
                                              "function",
                                              function->getName(),
                                              result.shard_count > 0,
                                              result.detail,
                                              result.shard_count));
    }

    if (suppressed_by_vm) {
      reports.push_back(make_transform_report(
          "opaque_predicates", "function", function->getName(), false, "suppressed after vm", 0));
    } else if (!state.report.decision.policy.allow_opaque_predicates) {
      reports.push_back(make_transform_report(
          "opaque_predicates",
          "function",
          function->getName(),
          false,
          function->isDeclaration() ? "declaration" : "policy disallows opaque predicates",
          0));
    } else {
      const opaque_predicate_options options =
          build_opaque_predicate_options(config, state.report.decision);
      const opaque_predicate_result result = analyze_opaque_predicates(*function, options);
      reports.push_back(make_transform_report("opaque_predicates",
                                              "function",
                                              function->getName(),
                                              result.insertion_count > 0,
                                              result.detail,
                                              result.insertion_count));
    }

    if (suppressed_by_vm) {
      reports.push_back(make_transform_report(
          "bogus_control_flow", "function", function->getName(), false, "suppressed after vm", 0));
    } else if (!state.report.decision.policy.allow_bogus_control_flow) {
      reports.push_back(make_transform_report(
          "bogus_control_flow",
          "function",
          function->getName(),
          false,
          function->isDeclaration() ? "declaration" : "policy disallows bogus control flow",
          0));
    } else {
      const bogus_control_flow_options options =
          build_bogus_control_flow_options(config, state.report.decision);
      const bogus_control_flow_result result = analyze_bogus_control_flow(*function, options);
      reports.push_back(make_transform_report("bogus_control_flow",
                                              "function",
                                              function->getName(),
                                              result.insertion_count > 0,
                                              result.detail,
                                              result.insertion_count));
    }
  }

  for (const function_pipeline_state& state : states) {
    if (state.function == nullptr) { continue; }
    if (state.mba_counts.linear_count == 0 && state.mba_counts.affine_count == 0 &&
        state.mba_counts.polynomial_count == 0 && state.mba_counts.mul_count == 0) {
      continue;
    }

    auto entry = make_transform_report(
        "mba", "function", state.function->getName(), true, "", 0);
    const std::size_t total = state.mba_counts.linear_count + state.mba_counts.affine_count +
                              state.mba_counts.polynomial_count + state.mba_counts.mul_count;
    entry.detail = "linear:" + std::to_string(state.mba_counts.linear_count) +
                   " affine:" + std::to_string(state.mba_counts.affine_count) +
                   " polynomial:" + std::to_string(state.mba_counts.polynomial_count) +
                   " mul:" + std::to_string(state.mba_counts.mul_count);
    entry.count = total;
    entry.has_mba_shape_payload = true;
    entry.mba_counts = state.mba_counts;
    reports.push_back(std::move(entry));
  }

  const llvm::StringMap<std::uint64_t> string_function_seeds = build_function_seed_map(
      states, [](const function_policy& policy) { return policy.allow_string_encoding; });
  const llvm::StringMap<protection_level> string_function_levels = build_function_level_map(
      states, [](const function_policy& policy) { return policy.allow_string_encoding; });
  const string_encoding_options string_options = build_string_encoding_options(config);
  const std::vector<string_encoding_result> string_results = analyze_string_encoding(
      module,
      [&](llvm::StringRef function_name) -> std::optional<std::uint64_t> {
        const auto iterator = string_function_seeds.find(function_name);
        if (iterator == string_function_seeds.end()) { return std::nullopt; }

        return iterator->second;
      },
      [&](llvm::StringRef function_name) -> std::optional<protection_level> {
        const auto iterator = string_function_levels.find(function_name);
        if (iterator == string_function_levels.end()) { return std::nullopt; }

        return iterator->second;
      },
      string_options,
      config.seed);

  for (const string_encoding_result& result : string_results) {
    const std::string detail =
        result.applied ? (to_string(result.mode) + ": " + result.detail) : result.detail;
    const std::size_t count = (result.mode == string_encoding_mode::lazy_decode ||
                               result.mode == string_encoding_mode::inline_stack_decode)
                                  ? result.rewritten_use_count
                                  : (result.applied ? 1U : 0U);
    transform_report_entry entry = make_transform_report(
        "string_encoding", "global", result.global_name, result.applied, detail, count);
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

  mba::clear_mba_counters();

  return reports;
}

}  // namespace obf
