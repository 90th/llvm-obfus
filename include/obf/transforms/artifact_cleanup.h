#pragma once

#include <cstdint>

namespace llvm {
class Module;
}

namespace obf {

struct artifact_cleanup_options {
  std::uint64_t seed = 0;
};

bool RunArtifactCleanup(llvm::Module &module,
                        const artifact_cleanup_options &options = {});

} // namespace obf
