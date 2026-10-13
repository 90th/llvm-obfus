#include "cpp-pe-lifetime-api.h"

extern "C" __attribute__((noinline)) U lifetime_text(U stage) {
  static constexpr unsigned char bytes[25] = {
      108, 105, 102, 101, 99,  121, 99,  108, 101, 45,  97, 117, 116,
      104, 45,  118, 49,  45,  112, 97,  121, 108, 111, 97, 100,
  };
  return bytes[stage % 25];
}

extern "C" __attribute__((noinline)) U lifetime_vm(U stage, U previous, U text) {
  U sum = previous;
  sum += UINT64_C(0x9e3779b97f4a7c15);
  sum += UINT64_C(0x100000001b3) * stage;
  U rotated = (sum % UINT64_C(0x20000000000000)) * 2048;
  rotated += sum / UINT64_C(0x20000000000000);
  return rotated ^ (UINT64_C(0xa0761d6478bd642f) * text);
}

extern "C" __attribute__((noinline)) U lifetime_step(U stage, U *effect) {
  U value = lifetime_vm(stage, *effect, lifetime_text(stage));
  U updated = 13 * stage + value;
  U result = updated ^ value;
  *effect = updated;
  return result;
}
