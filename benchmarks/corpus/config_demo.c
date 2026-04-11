#include <stdio.h>
#include <string.h>

#if defined(__clang__)
#define OBF_ANNOTATE(tag) __attribute__((annotate(tag)))
#else
#define OBF_ANNOTATE(tag)
#endif

static int OBF_ANNOTATE("obf:strong") parse_mode(const char *mode) {
  if (mode == NULL) {
    return 3;
  }

  if (strcmp(mode, "fast") == 0) {
    return 11;
  }

  if (strcmp(mode, "safe") == 0) {
    return 17;
  }

  return 5;
}

static int OBF_ANNOTATE("obf:light") fold_value(int value) {
  return (value ^ 0x1234) + 0x55;
}

int main(int argc, char **argv) {
  const char *mode = argc > 1 ? argv[1] : "safe";
  const int parsed = parse_mode(mode);
  const int folded = fold_value(parsed);

  printf("%s:%d\n", mode, folded);
  return 0;
}
