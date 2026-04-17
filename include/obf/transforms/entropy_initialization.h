#pragma once

namespace llvm {
class Module;
}

namespace obf {

bool RunEntropyInitialization(llvm::Module &module);

} // namespace obf
