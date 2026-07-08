#include <cstdint>
#include "obf/support/runtime_abi_generated.h"

extern "C" std::uint64_t OBF_RT_ENTROPY_ANCHOR;

int main() {
  return static_cast<int>(OBF_RT_ENTROPY_ANCHOR & 0ULL);
}
