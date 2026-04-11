#include <stddef.h>
#include <string.h>

#if defined(__clang__)
#define OBF_ANNOTATE(tag) __attribute__((annotate(tag)))
#define OBF_NOINLINE __attribute__((noinline))
#else
#define OBF_ANNOTATE(tag)
#define OBF_NOINLINE
#endif

OBF_NOINLINE int OBF_ANNOTATE("obf:strong") wpo_mix(const char *token) {
  int state = 0x2468;
  for (size_t i = 0; token[i] != '\0'; ++i) {
    state = (state << 3) ^ (state >> 1) ^ token[i] ^ 0x5a5a;
  }
  return state ^ 0x1122;
}

OBF_NOINLINE int OBF_ANNOTATE("obf:strong") wpo_check(const char *token) {
  return strcmp(token, "fusion") == 0 && wpo_mix(token) != 0;
}
