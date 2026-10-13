#include "cpp-elf-lifetime-api.h"

extern "C" __attribute__((noinline)) U lifetime_step(U stage, U generation,
                                                  U *effect) {
  static constexpr unsigned char text[25] = {
      108, 105, 102, 101, 99,  121, 99,  108, 101, 45,  97, 117, 116,
      104, 45,  118, 49,  45,  112, 97,  121, 108, 111, 97, 100,
  };
  U sum = generation * UINT64_C(0x9e3779b97f4a7c15);
  sum += *effect;
  sum += stage * UINT64_C(0x100000001b3);
  U rotated = sum >> 53;
  rotated |= sum << 11;
  U value = rotated ^
            (U{text[stage % 25]} * UINT64_C(0xa0761d6478bd642f));
  U updated = value + 13 * stage;
  *effect = updated;
  return updated ^ value;
}
