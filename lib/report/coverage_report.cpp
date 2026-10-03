#include "obf/report/coverage_report.h"

#include "obf/report/function_report.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/ADT/StringMap.h"
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <set>
#include <system_error>
#include <utility>
#include <vector>

namespace obf {

namespace {

constexpr llvm::StringLiteral coverage_marker = "obf.coverage";
constexpr llvm::StringLiteral coverage_events = "obf.coverage.events";
constexpr llvm::StringLiteral coverage_owner = "obf.coverage.owner";

const char* coverage_output_path() {
#if defined(_WIN32)
  static const auto owned_path = [] {
    char* value = nullptr;
    std::size_t length = 0;
    _dupenv_s(&value, &length, "OBF_COVERAGE_REPORT");
    return std::unique_ptr<char, decltype(&std::free)>(value, &std::free);
  }();
  const char* path = owned_path.get();
#else
  const char* path = std::getenv("OBF_COVERAGE_REPORT");
#endif
  return path != nullptr && *path != '\0' ? path : nullptr;
}

void append_snapshot(llvm::Module& module, llvm::json::Object snapshot) {
  start_coverage_reporting(module);
  snapshot["module"] = module.getModuleIdentifier();
  std::string payload;
  llvm::raw_string_ostream stream(payload);
  stream << llvm::json::Value(std::move(snapshot));
  llvm::MDString* text = llvm::MDString::get(module.getContext(), payload);
  module.getOrInsertNamedMetadata(coverage_events)
      ->addOperand(llvm::MDNode::get(module.getContext(), {text}));
}

llvm::StringRef policy_owner(const llvm::Module& module, llvm::StringRef target) {
  if (const llvm::Function* function = module.getFunction(target)) {
    if (const llvm::MDNode* metadata = function->getMetadata(coverage_owner)) {
      if (metadata->getNumOperands() == 1) {
        if (const auto* owner = llvm::dyn_cast<llvm::MDString>(metadata->getOperand(0))) {
          return owner->getString();
        }
      }
    }
  }
  return target;
}

}  // namespace

bool coverage_reporting_enabled(const llvm::Module& module) {
  return module.getNamedMetadata(coverage_marker) != nullptr || coverage_output_path() != nullptr;
}

void start_coverage_reporting(llvm::Module& module) {
  llvm::NamedMDNode* marker = module.getOrInsertNamedMetadata(coverage_marker);
  if (marker->getNumOperands() == 0) {
    marker->addOperand(llvm::MDNode::get(module.getContext(),
                                        {llvm::MDString::get(module.getContext(), "v1")}));
  }
}

void record_coverage_event(llvm::Module& module,
                           llvm::StringRef stage,
                           llvm::StringRef mechanism,
                           llvm::StringRef owner,
                           llvm::StringRef target,
                           llvm::StringRef status,
                           llvm::StringRef reason,
                           std::size_t count,
                           llvm::StringRef scope) {
  if (!coverage_reporting_enabled(module)) { return; }

  llvm::json::Object snapshot;
  snapshot["stage"] = stage.str();
  snapshot["mechanism"] = mechanism.str();
  snapshot["owner"] = owner.str();
  snapshot["target"] = target.str();
  snapshot["status"] = status.str();
  snapshot["reason"] = reason.str();
  snapshot["count"] = static_cast<std::int64_t>(count);
  snapshot["scope"] = scope.str();
  append_snapshot(module, std::move(snapshot));
}

void record_coverage_role(llvm::Function& function,
                          llvm::StringRef owner,
                          llvm::StringRef role,
                          llvm::ArrayRef<llvm::StringRef> obligations) {
  llvm::Module* module = function.getParent();
  if (module == nullptr || !coverage_reporting_enabled(*module)) { return; }

  llvm::StringRef metadata_owner = owner;
  if (const llvm::MDNode* existing = function.getMetadata(coverage_owner)) {
    if (existing->getNumOperands() == 1) {
      if (const auto* name = llvm::dyn_cast<llvm::MDString>(existing->getOperand(0))) {
        if (name->getString() != owner) { metadata_owner = ""; }
      }
    }
  }
  function.setMetadata(coverage_owner,
                       llvm::MDNode::get(function.getContext(),
                                         {llvm::MDString::get(function.getContext(), metadata_owner)}));
  llvm::json::Object snapshot;
  snapshot["stage"] = "roles";
  snapshot["owner"] = owner.str();
  snapshot["target"] = function.getName().str();
  snapshot["role"] = role.str();
  llvm::json::Array obligations_json;
  for (llvm::StringRef obligation : obligations) {
    obligations_json.push_back(obligation.str());
  }
  snapshot["obligations"] = std::move(obligations_json);
  append_snapshot(*module, std::move(snapshot));
}

void record_coverage_policy(llvm::Module& module,
                            const function_report_entry& entry,
                            llvm::StringRef phase) {
  if (!coverage_reporting_enabled(module)) { return; }

  llvm::json::Object snapshot;
  snapshot["stage"] = "policy";
  snapshot["phase"] = phase.str();
  snapshot["owner"] = policy_owner(module, entry.features.name).str();
  snapshot["target"] = entry.features.name;
  snapshot["scope"] = "function";
  snapshot["policy"] = build_policy_report(entry.decision);
  if (!entry.annotation.empty()) { snapshot["annotation"] = entry.annotation; }
  append_snapshot(module, std::move(snapshot));
}

std::string format_coverage_report(const llvm::Module& module) {
  llvm::json::Object root;
  root["schema"] = "obf.coverage_report.v1";
  root["module"] = module.getName().str();
  root["evidence"] = "compiler_report";
  root["capture"] = coverage_reporting_enabled(module) ? "enabled" : "not_enabled";
  root["absent_outcome"] = "not_observed";
  root["requested_policy"] = llvm::json::Array();
  root["admission"] = llvm::json::Array();
  root["emission"] = llvm::json::Array();
  root["finalization"] = llvm::json::Array();
  root["roles"] = llvm::json::Array();

  if (const llvm::NamedMDNode* ledger = module.getNamedMetadata(coverage_events)) {
    for (const llvm::MDNode* node : ledger->operands()) {
      if (node->getNumOperands() != 1) {
        llvm::report_fatal_error("obf-coverage-report: malformed coverage snapshot");
      }
      const auto* text = llvm::dyn_cast<llvm::MDString>(node->getOperand(0));
      if (text == nullptr) {
        llvm::report_fatal_error("obf-coverage-report: snapshot must contain a JSON string");
      }
      auto parsed = llvm::json::parse(text->getString());
      if (!parsed) {
        llvm::report_fatal_error(llvm::Twine("obf-coverage-report: invalid snapshot JSON: ") +
                                 llvm::toString(parsed.takeError()));
      }
      llvm::json::Object* snapshot = parsed->getAsObject();
      const auto stage = snapshot != nullptr ? snapshot->getString("stage") : std::nullopt;
      if (!stage) {
        llvm::report_fatal_error("obf-coverage-report: snapshot has no stage");
      }
      llvm::json::Array* events = root.getArray(*stage == "policy" ? "requested_policy" : *stage);
      if (events == nullptr) {
        llvm::report_fatal_error(llvm::Twine("obf-coverage-report: unknown snapshot stage: ") + *stage);
      }
      snapshot->erase("stage");
      events->push_back(std::move(*parsed));
    }
  }

  // Resolve lexical helper parents only through recorded creation relationships.
  llvm::StringMap<llvm::StringMap<std::set<std::string>>> parents;
  for (const llvm::json::Value& value : *root.getArray("roles")) {
    const llvm::json::Object& role = *value.getAsObject();
    const auto owner = role.getString("owner");
    const auto target = role.getString("target");
    const auto origin = role.getString("module");
    if (owner && target && origin && !owner->empty() && *owner != *target) {
      parents[*origin][*target].insert(owner->str());
    }
  }
  for (llvm::StringRef stage : {"requested_policy", "admission", "emission", "finalization", "roles"}) {
    for (llvm::json::Value& value : *root.getArray(stage)) {
      llvm::json::Object& event = *value.getAsObject();
      const auto owner = event.getString("owner");
      const auto origin = event.getString("module");
      const auto target = event.getString("target");
      if (!owner || !origin || !target) { continue; }
      const llvm::StringRef lexical_owner = owner->empty() ? *target : *owner;
      const auto module_parents = parents.find(*origin);
      if (module_parents == parents.end() ||
          !module_parents->second.contains(lexical_owner)) {
        continue;
      }
      const std::string immediate_owner = lexical_owner.str();
      std::vector<std::string> pending{immediate_owner};
      std::set<std::string> visited;
      std::set<std::string> originals;
      while (!pending.empty()) {
        std::string current = std::move(pending.back());
        pending.pop_back();
        if (!visited.insert(current).second) { continue; }
        const auto parent = module_parents->second.find(current);
        if (parent == module_parents->second.end()) {
          originals.insert(std::move(current));
        } else {
          pending.insert(pending.end(), parent->second.begin(), parent->second.end());
        }
      }
      if (originals.size() == 1 && *originals.begin() == immediate_owner) { continue; }
      event["parent"] = immediate_owner;
      event["owner"] = originals.size() == 1 ? *originals.begin() : "";
      if (originals.size() != 1) {
        llvm::json::Array owners;
        for (const std::string& original : originals) { owners.push_back(original); }
        event["owners"] = std::move(owners);
        event["owner_resolution"] = originals.empty() ? "unresolved" : "shared";
      }
    }
  }

  std::string output;
  llvm::raw_string_ostream stream(output);
  stream << llvm::json::Value(std::move(root));
  return output;
}

void write_coverage_report(llvm::Module& module) {
  if (!coverage_reporting_enabled(module)) { return; }
  const char* path = coverage_output_path();
  if (path == nullptr) { return; }

  std::error_code error;
  llvm::raw_fd_ostream output(path, error, llvm::sys::fs::OF_Text);
  if (error) {
    llvm::errs() << "obf-coverage-report: cannot open '" << path << "': " << error.message() << '\n';
    return;
  }
  output << format_coverage_report(module) << '\n';
  output.flush();
  if (output.has_error()) {
    llvm::errs() << "obf-coverage-report: cannot write '" << path << "': "
                 << output.error().message() << '\n';
    output.clear_error();
  }
}

}  // namespace obf
