#include "obf/frontend/annotations.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"

namespace obf {

function_annotation_map collect_function_annotations(const llvm::Module& module) {
  function_annotation_map annotations;

  const llvm::GlobalVariable* annotation_global = module.getNamedGlobal("llvm.global.annotations");
  if (annotation_global == nullptr || !annotation_global->hasInitializer()) { return annotations; }

  const auto* annotation_array =
      llvm::dyn_cast<llvm::ConstantArray>(annotation_global->getInitializer());
  if (annotation_array == nullptr) { return annotations; }

  for (const llvm::Use& entry_use : annotation_array->operands()) {
    const auto* entry = llvm::dyn_cast<llvm::ConstantStruct>(entry_use.get());
    if (entry == nullptr || entry->getNumOperands() < 2) { continue; }

    const auto* function =
        llvm::dyn_cast<llvm::Function>(entry->getOperand(0)->stripPointerCasts());
    const auto* text_global =
        llvm::dyn_cast<llvm::GlobalVariable>(entry->getOperand(1)->stripPointerCasts());

    if (function == nullptr || text_global == nullptr || !text_global->hasInitializer()) {
      continue;
    }

    const auto* text_data =
        llvm::dyn_cast<llvm::ConstantDataSequential>(text_global->getInitializer());
    if (text_data == nullptr || !text_data->isCString()) { continue; }

    annotations[function->getName()] = text_data->getAsCString().str();
  }

  return annotations;
}

const std::string* find_function_annotation(const function_annotation_map& annotations,
                                            llvm::StringRef function_name) {
  const auto iterator = annotations.find(function_name);
  if (iterator == annotations.end()) { return nullptr; }

  return &iterator->second;
}

}  // namespace obf
