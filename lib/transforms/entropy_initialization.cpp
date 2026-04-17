#include "obf/transforms/entropy_initialization.h"

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/ADT/Twine.h"

#include <cstdint>
#include <system_error>

namespace obf {
namespace {

constexpr char kEntropyAnchorName[] = "__obf_entropy_anchor";

std::uint64_t GetSecureRandomWord() {
  std::uint64_t word = 0;
  do {
    const std::error_code error = llvm::getRandomBytes(&word, sizeof(word));
    if (error) {
      llvm::report_fatal_error(
          llvm::Twine(
              "failed to source secure randomness for __obf_entropy_anchor: ") +
          error.message());
    }
  } while (word == 0);

  return word;
}

} // namespace

bool RunEntropyInitialization(llvm::Module &module) {
  llvm::GlobalVariable *entropy_anchor =
      module.getNamedGlobal(kEntropyAnchorName);
  if (entropy_anchor == nullptr || entropy_anchor->isDeclaration() ||
      !entropy_anchor->getValueType()->isIntegerTy(64)) {
    return false;
  }

  std::uint64_t current_word = 0;
  const llvm::Constant *initializer = entropy_anchor->getInitializer();
  if (initializer == nullptr) {
    return false;
  }

  if (const auto *integer_initializer =
          llvm::dyn_cast<llvm::ConstantInt>(initializer)) {
    current_word = integer_initializer->getZExtValue();
  }

  std::uint64_t random_word = 0;
  do {
    random_word = GetSecureRandomWord();
  } while (random_word == current_word);

  entropy_anchor->setInitializer(
      llvm::ConstantInt::get(entropy_anchor->getValueType(), random_word));
  return true;
}

} // namespace obf
