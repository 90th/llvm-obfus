#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#if defined(__clang__)
#define OBF_ANNOTATE(tag) __attribute__((annotate(tag)))
#else
#define OBF_ANNOTATE(tag)
#endif

static uint64_t now_ns(void) {
  struct timespec ts;
  timespec_get(&ts, TIME_UTC);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t get_bench_iters(void) {
  const char *text = getenv("OBF_BENCH_ITERS");
  if (text == NULL || *text == '\0') {
    return 0;
  }
  return strtoull(text, NULL, 10);
}

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
  const uint64_t iters = get_bench_iters();
  if (iters > 0) {
    static const char *kModes[] = {"fast", "safe", "guest"};
    volatile uint64_t sink = 0;

    for (uint64_t i = 0; i < 2048; ++i) {
      const char *mode = kModes[i % 3];
      const int parsed = parse_mode(mode);
      const int folded = fold_value(parsed);
      sink ^= (uint64_t)(unsigned int)folded;
    }

    const uint64_t start_ns = now_ns();
    for (uint64_t i = 0; i < iters; ++i) {
      const char *mode = kModes[i % 3];
      const int parsed = parse_mode(mode);
      const int folded = fold_value(parsed);
      sink ^= (uint64_t)(unsigned int)folded;
    }
    const uint64_t end_ns = now_ns();
    const double ns_per_iter = (double)(end_ns - start_ns) / (double)iters;
    printf("BENCH config_demo ns/op=%.2f sink=%llu\n", ns_per_iter,
           (unsigned long long)sink);
    return 0;
  }

  const char *mode = argc > 1 ? argv[1] : "safe";
  const int parsed = parse_mode(mode);
  const int folded = fold_value(parsed);

  printf("%s:%d\n", mode, folded);
  return 0;
}
