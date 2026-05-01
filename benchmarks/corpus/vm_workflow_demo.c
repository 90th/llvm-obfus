#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#if defined(__clang__)
#define OBF_NOINLINE __attribute__((noinline))
#else
#define OBF_NOINLINE
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

static const uint32_t kLaneWeights[4] = {3u, 7u, 11u, 19u};

static OBF_NOINLINE uint32_t classify_byte(unsigned char byte, uint32_t salt) {
  switch ((byte ^ salt) & 3u) {
  case 0:
    return (uint32_t)byte + 3u;
  case 1:
    return ((uint32_t)byte << 1) ^ 0x5au;
  case 2:
    return (uint32_t)byte * 7u + 1u;
  default:
    return ((uint32_t)byte ^ 0x33u) - 9u;
  }
}

static OBF_NOINLINE uint32_t route_score(const unsigned char *text, size_t len,
                                         uint32_t bias, uint32_t *accum_out) {
  uint32_t state = bias ^ 0x13579bdu;

  for (size_t i = 0; i < len; ++i) {
    const uint32_t lane = classify_byte(text[i], (uint32_t)i + bias);
    const uint32_t weight = kLaneWeights[i & 3u];

    switch ((lane + weight + (uint32_t)i) & 3u) {
    case 0:
      state = state + lane + weight;
      break;
    case 1:
      state = (state ^ lane) + weight;
      break;
    case 2:
      state = state + (lane ^ weight);
      break;
    default:
      state = (state << 1) ^ lane ^ weight;
      break;
    }

    if ((lane & 1u) == 0) {
      *accum_out += lane;
    } else {
      *accum_out ^= weight;
    }
  }

  return state ^ *accum_out;
}

int main(int argc, char **argv) {
  const unsigned char *token =
      (const unsigned char *)(argc > 1 ? argv[1] : "guest-path");
  const uint64_t iters = get_bench_iters();

  if (iters > 0) {
    const size_t len = strlen((const char *)token);
    volatile uint64_t sink = 0;

    for (uint64_t i = 0; i < 1024; ++i) {
      uint32_t accum_local = 0;
      const uint32_t score = route_score(token, len, 0x2468u ^ (uint32_t)(i & 0xffu),
                                         &accum_local);
      sink ^= (uint64_t)score ^ (uint64_t)accum_local;
    }

    const uint64_t start_ns = now_ns();
    for (uint64_t i = 0; i < iters; ++i) {
      uint32_t accum_local = 0;
      const uint32_t score = route_score(token, len, 0x2468u ^ (uint32_t)(i & 0xffu),
                                         &accum_local);
      sink ^= (uint64_t)score ^ (uint64_t)accum_local;
    }
    const uint64_t end_ns = now_ns();
    const double ns_per_iter = (double)(end_ns - start_ns) / (double)iters;
    printf("BENCH vm_workflow_demo ns/op=%.2f sink=%llu\n", ns_per_iter,
           (unsigned long long)sink);
    return 0;
  }

  uint32_t accum = 0;
  const uint32_t score =
      route_score(token, strlen((const char *)token), 0x2468u, &accum);

  printf("route:%u:%u\n", accum, score);
  return (score & 1u) != 0 ? 0 : 1;
}
