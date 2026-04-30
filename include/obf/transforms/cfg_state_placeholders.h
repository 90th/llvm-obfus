#ifndef OBF_TRANSFORMS_CFG_STATE_PLACEHOLDERS_H
#define OBF_TRANSFORMS_CFG_STATE_PLACEHOLDERS_H

#include "llvm/ADT/StringRef.h"

namespace obf {

inline constexpr llvm::StringRef kCfgStatePlaceholderName =
    "__obf_get_cfg_state";
inline constexpr llvm::StringRef kExpectedCfgStatePlaceholderName =
    "__obf_get_expected_cfg_state";

} // namespace obf

#endif // OBF_TRANSFORMS_CFG_STATE_PLACEHOLDERS_H