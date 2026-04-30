#pragma once

#include <cstdint>

namespace llvm {
class Module;
}

namespace obf {

bool RunEntropyInitialization(llvm::Module &module,
                              std::uint64_t seed_override = 0);

} // namespace obf
