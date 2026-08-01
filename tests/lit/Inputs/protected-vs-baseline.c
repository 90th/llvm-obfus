#include <stdint.h>
#include <stdio.h>

static const char kProtectedSecret[] = "baseline-visible-secret";

__attribute__((noinline))
static uint32_t protected_value(uint32_t salt) {
  const unsigned char *message = (const unsigned char *)kProtectedSecret;
  uint32_t acc = salt;
  while (*message != '\0') {
    acc = (acc * UINT32_C(131)) ^ *message;
    ++message;
  }
  return acc & UINT32_C(0xffff);
}

int main(int argc, char **argv) {
  (void)argv;
  uint32_t digest = protected_value((uint32_t)argc + UINT32_C(40));
  printf("digest=%u len=%zu\n", (unsigned)digest, sizeof(kProtectedSecret) - 1);
  return 0;
}
