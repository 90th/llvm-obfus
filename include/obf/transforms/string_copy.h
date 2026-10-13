#pragma once

#include <cstdint>

namespace llvm {
class Constant;
class GlobalVariable;
class Module;
}  // namespace llvm

namespace obf {

// Generate accessors before policy selection and native ownership capture.
bool prepare_string_copy_exports(llvm::Module& module);
bool is_string_copy_source(const llvm::GlobalVariable& global);

// Bind only after an authenticated lazy or constructor plan succeeds.
// The private payload helper is i32(ptr source, ptr destination).
// Its source operand retains the original compiler ownership dependency.
void bind_string_copy_authentication(llvm::GlobalVariable& source,
                                     llvm::Constant* descriptor,
                                     llvm::Constant* topology,
                                     std::uint64_t length,
                                     std::uint64_t binding);

// Validate live decoder calls and private source bindings before cleanup.
void validate_string_copy_exports(llvm::Module& module);

}  // namespace obf
