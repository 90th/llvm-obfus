#ifndef OBF_TRANSFORMS_CFG_STATE_PLACEHOLDERS_H
#define OBF_TRANSFORMS_CFG_STATE_PLACEHOLDERS_H

#include "llvm/ADT/StringRef.h"

namespace obf {

/// \brief Placeholder function name for runtime CFG state retrieval.
///
/// Used during control flow flattening and state cleanup to inject
/// runtime calls that retrieve the current CFG state. The actual implementation
/// is provided by the CFG state cleanup pass via function outlining.
///
/// \note Value: "__obf_get_cfg_state"
/// \see apply_cfg_state_cleanup_stage, control_flattening.h
inline constexpr llvm::StringRef kCfgStatePlaceholderName = "__obf_get_cfg_state";

/// \brief Placeholder function name for expected CFG state validation.
///
/// Used during integrity checking to validate that the CFG state matches
/// expected values at critical control flow points. Helps detect control flow
/// integrity violations and tampering attempts.
///
/// \note Value: "__obf_get_expected_cfg_state"
/// \see apply_cfg_state_cleanup_stage, opaque_predicates.h
inline constexpr llvm::StringRef kExpectedCfgStatePlaceholderName = "__obf_get_expected_cfg_state";

}  // namespace obf

#endif  // OBF_TRANSFORMS_CFG_STATE_PLACEHOLDERS_H