#include "obf/report/function_report.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>

namespace obf {

llvm::json::Object build_policy_report(const policy_decision& decision) {
  llvm::json::Object policy_json;
  policy_json["level"] = std::string(to_string(decision.policy.level));
  policy_json["source"] = std::string(to_string(decision.source));
  policy_json["detail"] = decision.detail;
  policy_json["seed"] = "0x" + llvm::utohexstr(decision.seed, true);
  if (decision.minimum_security_floor.has_value()) {
    policy_json["minimum_security_floor"] =
        std::string(to_string(*decision.minimum_security_floor));
  }
  policy_json["allow_string_encoding"] = decision.policy.allow_string_encoding;
  policy_json["allow_zero_comparison"] = decision.policy.allow_zero_comparison;
  policy_json["allow_constant_encoding"] = decision.policy.allow_constant_encoding;
  policy_json["allow_instruction_substitution"] = decision.policy.allow_instruction_substitution;
  policy_json["allow_opaque_gep"] = decision.policy.allow_opaque_gep;
  policy_json["allow_function_outlining"] = decision.policy.allow_function_outlining;
  policy_json["allow_bogus_control_flow"] = decision.policy.allow_bogus_control_flow;
  policy_json["allow_opaque_predicates"] = decision.policy.allow_opaque_predicates;
  policy_json["allow_flattening"] = decision.policy.allow_flattening;
  policy_json["allow_split"] = decision.policy.allow_split;
  policy_json["allow_indirect_calls"] = decision.policy.allow_indirect_calls;
  policy_json["allow_vm"] = decision.policy.allow_vm;
  policy_json["allow_self_checksum"] = decision.policy.allow_self_checksum;
  return policy_json;
}

std::string format_feature_report(llvm::StringRef module_name,
                                  llvm::ArrayRef<function_report_entry> entries,
                                  llvm::ArrayRef<prediction_report_entry> predictions,
                                  llvm::ArrayRef<structural_observation_report_entry> observations) {
  llvm::json::Array functions_json;
  llvm::json::Array predictions_json;
  llvm::json::Array observations_json;

  for (const function_report_entry& entry : entries) {
    const function_features& feature = entry.features;
    llvm::json::Object function_json;
    function_json["name"] = feature.name;
    function_json["instruction_count"] = static_cast<std::int64_t>(feature.instruction_count);
    function_json["basic_block_count"] = static_cast<std::int64_t>(feature.basic_block_count);
    function_json["cyclomatic_complexity"] =
        static_cast<std::int64_t>(feature.cyclomatic_complexity);
    function_json["call_count"] = static_cast<std::int64_t>(feature.call_count);
    function_json["string_ref_count"] = static_cast<std::int64_t>(feature.string_ref_count);
    function_json["has_loops"] = feature.has_loops;
    function_json["has_exception_edges"] = feature.has_exception_edges;
    function_json["has_inline_asm"] = feature.has_inline_asm;
    function_json["has_vector_ops"] = feature.has_vector_ops;
    function_json["is_recursive"] = feature.is_recursive;
    function_json["address_taken"] = feature.address_taken;
    function_json["is_declaration"] = feature.is_declaration;

    function_json["policy"] = build_policy_report(entry.decision);

    if (!entry.annotation.empty()) { function_json["annotation"] = entry.annotation; }

    functions_json.push_back(llvm::json::Value(std::move(function_json)));
  }

  for (const prediction_report_entry& entry : predictions) {
    llvm::json::Object prediction_json;
    prediction_json["pass"] = entry.pass;
    prediction_json["target_kind"] = entry.target_kind;
    prediction_json["target_name"] = entry.target_name;
    prediction_json["status"] = entry.status;
    prediction_json["evidence"] = "candidate_analysis";
    prediction_json["detail"] = entry.detail;
    prediction_json["count"] = static_cast<std::int64_t>(entry.count);

    if (entry.has_strategy_payload) {
      llvm::json::Object strategy_json;
      strategy_json["kind"] = entry.strategy_kind;
      strategy_json["helper_shape"] = entry.helper_shape;
      strategy_json["key_schedule"] = entry.key_schedule;
      strategy_json["inline_eligible"] = entry.inline_eligible;
      strategy_json["inline_detail"] = entry.inline_detail;
      strategy_json["fallback_reason"] = entry.fallback_reason;
      strategy_json["protected_use_count"] = static_cast<std::int64_t>(entry.protected_use_count);
      strategy_json["unprotected_use_count"] =
          static_cast<std::int64_t>(entry.unprotected_use_count);
      if (entry.descriptor_index >= 0) {
        strategy_json["descriptor_index"] = entry.descriptor_index;
      }

      if (entry.merge_group >= 0) { strategy_json["merge_group"] = entry.merge_group; }

      llvm::json::Array use_kinds_json;
      for (const std::string& use_kind : entry.use_kinds) { use_kinds_json.push_back(use_kind); }
      strategy_json["use_kinds"] = std::move(use_kinds_json);
      prediction_json["strategy"] = llvm::json::Value(std::move(strategy_json));
    }

    predictions_json.push_back(llvm::json::Value(std::move(prediction_json)));
  }

  for (const structural_observation_report_entry& entry : observations) {
    llvm::json::Object observation_json;
    observation_json["mechanism"] = entry.mechanism;
    observation_json["target_kind"] = entry.target_kind;
    observation_json["target_name"] = entry.target_name;
    observation_json["status"] = "observed";
    observation_json["evidence"] = "structural_observation";
    observation_json["detail"] = entry.detail;
    observation_json["count"] = static_cast<std::int64_t>(entry.count);
    llvm::json::Object mba_json;
    mba_json["linear"] = static_cast<std::int64_t>(entry.mba_counts.linear_count);
    mba_json["affine"] = static_cast<std::int64_t>(entry.mba_counts.affine_count);
    mba_json["polynomial"] = static_cast<std::int64_t>(entry.mba_counts.polynomial_count);
    mba_json["mul"] = static_cast<std::int64_t>(entry.mba_counts.mul_count);
    observation_json["mba"] = std::move(mba_json);
    observations_json.push_back(std::move(observation_json));
  }

  llvm::json::Object root;
  root["schema"] = "obf.feature_report.v4";
  root["module"] = module_name.str();
  root["function_count"] = static_cast<std::int64_t>(entries.size());
  root["functions"] = std::move(functions_json);
  root["predictions"] = std::move(predictions_json);
  root["observations"] = std::move(observations_json);

  std::string output;
  llvm::raw_string_ostream stream(output);
  stream << llvm::json::Value(std::move(root));
  return output;
}

}  // namespace obf
