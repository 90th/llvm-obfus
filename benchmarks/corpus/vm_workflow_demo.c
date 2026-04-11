#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(__clang__)
#define OBF_NOINLINE __attribute__((noinline))
#else
#define OBF_NOINLINE
#endif

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
  uint32_t accum = 0;
  const uint32_t score =
      route_score(token, strlen((const char *)token), 0x2468u, &accum);

  printf("route:%u:%u\n", accum, score);
  return (score & 1u) != 0 ? 0 : 1;
}
