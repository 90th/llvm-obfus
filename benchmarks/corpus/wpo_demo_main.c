#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

int wpo_check(const char *token);
int wpo_mix(const char *token);

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

int main(int argc, char **argv) {
  const char *token = argc > 1 ? argv[1] : "guest";

  const uint64_t iters = get_bench_iters();
  if (iters > 0) {
    volatile uint64_t sink = 0;

    for (uint64_t i = 0; i < 1024; ++i) {
      const int ok = wpo_check(token);
      const int score = wpo_mix(token);
      sink ^= (uint64_t)(unsigned int)ok;
      sink ^= (uint64_t)(unsigned int)score;
    }

    const uint64_t start_ns = now_ns();
    for (uint64_t i = 0; i < iters; ++i) {
      const int ok = wpo_check(token);
      const int score = wpo_mix(token);
      sink ^= (uint64_t)(unsigned int)ok;
      sink ^= (uint64_t)(unsigned int)score;
    }
    const uint64_t end_ns = now_ns();
    const double ns_per_iter = (double)(end_ns - start_ns) / (double)iters;
    printf("BENCH wpo_demo ns/op=%.2f sink=%llu\n", ns_per_iter,
           (unsigned long long)sink);
    return 0;
  }

  const int ok = wpo_check(token);
  const int score = wpo_mix(token);
  puts(ok ? "WPO OK" : "WPO FAIL");
  printf("%d\n", score);
  return ok ? 0 : 1;
}
