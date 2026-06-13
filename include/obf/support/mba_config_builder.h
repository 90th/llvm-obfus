#pragma once

#include "obf/frontend/config.h"

#include "llvm/ADT/StringRef.h"

#include <cstdint>

namespace llvm {
class Function;
}  // namespace llvm

namespace obf {

namespace mba {
struct builder_context;
}  // namespace mba

namespace support {

mba::builder_context make_mba_context(llvm::Function& function,
                                       llvm::StringRef prefix,
                                       std::uint64_t seed_base,
                                       const mba_config& cfg);

}  // namespace support

}  // namespace obf
