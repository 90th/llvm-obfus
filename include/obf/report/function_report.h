#pragma once

#include "obf/analysis/function_features.h"
#include "obf/policy/policy_engine.h"
#include "obf/transforms/mba.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"

#include <string>
#include <vector>

namespace llvm::json {
class Object;
}

namespace obf {

struct function_report_entry {
  function_features features;
  policy_decision decision;
  std::string annotation;
};

struct prediction_report_entry {
  std::string pass;
  std::string target_kind;
  std::string target_name;
  std::string status;
  std::string detail;
  std::size_t count = 0;
  std::string strategy_kind;
  std::string helper_shape;
  std::string key_schedule;
  std::string inline_detail;
  std::string fallback_reason;
  int merge_group = -1;
  int descriptor_index = -1;
  std::size_t protected_use_count = 0;
  std::size_t unprotected_use_count = 0;
  bool inline_eligible = false;
  bool has_strategy_payload = false;
  std::vector<std::string> use_kinds;
};

struct structural_observation_report_entry {
  std::string mechanism;
  std::string target_kind;
  std::string target_name;
  std::string detail;
  std::size_t count = 0;
  mba::mba_shape_counts mba_counts;
};

llvm::json::Object build_policy_report(const policy_decision& decision);

std::string format_feature_report(llvm::StringRef module_name,
                                  llvm::ArrayRef<function_report_entry> entries,
                                  llvm::ArrayRef<prediction_report_entry> predictions,
                                  llvm::ArrayRef<structural_observation_report_entry> observations);

}  // namespace obf
