#pragma once

#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringRef.h"

#include <string>

namespace llvm {
class Module;
}

namespace obf {

using function_annotation_map = llvm::StringMap<std::string>;

function_annotation_map collect_function_annotations(const llvm::Module& module);
const std::string* find_function_annotation(const function_annotation_map& annotations,
                                            llvm::StringRef function_name);

}  // namespace obf
