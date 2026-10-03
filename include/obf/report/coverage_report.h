#pragma once

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"

#include <cstddef>
#include <string>

namespace llvm {
class Function;
class Module;
}

namespace obf {

struct function_report_entry;

bool coverage_reporting_enabled(const llvm::Module& module);
void start_coverage_reporting(llvm::Module& module);

// These snapshots describe compiler stages, not runtime execution or security.
void record_coverage_event(llvm::Module& module,
                           llvm::StringRef stage,
                           llvm::StringRef mechanism,
                           llvm::StringRef owner,
                           llvm::StringRef target,
                           llvm::StringRef status,
                           llvm::StringRef reason,
                           std::size_t count = 0,
                           llvm::StringRef scope = "function");
void record_coverage_role(llvm::Function& function,
                          llvm::StringRef owner,
                          llvm::StringRef role,
                          llvm::ArrayRef<llvm::StringRef> obligations);
void record_coverage_policy(llvm::Module& module,
                            const function_report_entry& entry,
                            llvm::StringRef phase = "selected");

std::string format_coverage_report(const llvm::Module& module);
void write_coverage_report(llvm::Module& module);

}  // namespace obf
