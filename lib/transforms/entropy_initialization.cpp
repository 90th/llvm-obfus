#include "obf/transforms/entropy_initialization.h"

#include "obf/support/stable_hash.h"

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

std::uint64_t mix_entropy_seed(std::uint64_t seed, std::uint64_t salt) {
  seed ^= salt + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
  return seed;
}

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

std::uint64_t GetSeededWord(std::uint64_t seed_override, std::uint64_t current_word) {
  std::uint64_t seeded_word = mix_entropy_seed(
      seed_override, stable_hash_string(kEntropyAnchorName));
  seeded_word = mix_entropy_seed(seeded_word, 0x454e54524f505901ULL);
  if (seeded_word == 0) {
    seeded_word = 0x6a09e667f3bcc909ULL;
  }
  if (seeded_word == current_word) {
    seeded_word = mix_entropy_seed(seeded_word, 0x454e54524f505902ULL);
    if (seeded_word == 0) {
      seeded_word = 0xbb67ae8584caa73bULL;
    }
  }
  return seeded_word;
}

} // namespace

bool RunEntropyInitialization(llvm::Module &module, std::uint64_t seed_override) {
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

  const std::uint64_t random_word =
      seed_override != 0 ? GetSeededWord(seed_override, current_word)
                         : [&]() {
                             std::uint64_t fresh_word = 0;
                             do {
                               fresh_word = GetSecureRandomWord();
                             } while (fresh_word == current_word);
                             return fresh_word;
                           }();

  entropy_anchor->setInitializer(
      llvm::ConstantInt::get(entropy_anchor->getValueType(), random_word));
  return true;
}

} // namespace obf
