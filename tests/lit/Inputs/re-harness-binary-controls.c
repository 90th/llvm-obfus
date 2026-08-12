#include <stddef.h>
#include <stdint.h>

#ifndef CONTROL_KIND
#define CONTROL_KIND 1
#endif

#ifndef STRUCTURAL_VARIANT
#define STRUCTURAL_VARIANT 0
#endif

#if defined(__clang__) || defined(__GNUC__)
#define CONTROL_NOINLINE __attribute__((noinline))
#else
#define CONTROL_NOINLINE
#endif

static uint32_t rotate_left(uint32_t value, uint32_t count) {
  count &= 31u;
  return (value << count) | (value >> ((32u - count) & 31u));
}

static uint32_t mix_word(uint32_t value) {
  value ^= value >> 16;
  value *= UINT32_C(0x7feb352d);
  value ^= value >> 15;
  value *= UINT32_C(0x846ca68b);
  return value ^ (value >> 16);
}

#if CONTROL_KIND == 1
static uint32_t large_switch_value(uint32_t selector) {
#if STRUCTURAL_VARIANT
  static const uint32_t lower_values[16] = {
      UINT32_C(0x54a1c3e7), UINT32_C(0x17d94b2f), UINT32_C(0xa2f56981),
      UINT32_C(0x6c7e13b5), UINT32_C(0xd45f9823), UINT32_C(0x2b81e64d),
      UINT32_C(0x91c4ab37), UINT32_C(0x0f73d9a9), UINT32_C(0xbed25641),
      UINT32_C(0x43ea8f1d), UINT32_C(0x79b10ce3), UINT32_C(0xc682754f),
      UINT32_C(0x35adf219), UINT32_C(0xe14c679b), UINT32_C(0x8a36bd05),
      UINT32_C(0x5d9728d1),
  };
  static const uint32_t upper_values[16] = {
      UINT32_C(0xf03ba46b), UINT32_C(0x28c5e719), UINT32_C(0x9d610f53),
      UINT32_C(0x467a32cd), UINT32_C(0xb783d8a5), UINT32_C(0x1ce94f87),
      UINT32_C(0x72ad165b), UINT32_C(0xcb508931), UINT32_C(0x3f6cda97),
      UINT32_C(0x84e1250b), UINT32_C(0x1597bc6d), UINT32_C(0xae42f803),
      UINT32_C(0x61d30aef), UINT32_C(0xd8b56c49), UINT32_C(0x07fe9137),
      UINT32_C(0x9a2845c1),
  };
  uint32_t index = selector & 15u;
  return (selector & 16u) == 0u ? lower_values[index] : upper_values[index];
#else
  switch (selector & 31u) {
  case 0:
    return UINT32_C(0x54a1c3e7);
  case 1:
    return UINT32_C(0x17d94b2f);
  case 2:
    return UINT32_C(0xa2f56981);
  case 3:
    return UINT32_C(0x6c7e13b5);
  case 4:
    return UINT32_C(0xd45f9823);
  case 5:
    return UINT32_C(0x2b81e64d);
  case 6:
    return UINT32_C(0x91c4ab37);
  case 7:
    return UINT32_C(0x0f73d9a9);
  case 8:
    return UINT32_C(0xbed25641);
  case 9:
    return UINT32_C(0x43ea8f1d);
  case 10:
    return UINT32_C(0x79b10ce3);
  case 11:
    return UINT32_C(0xc682754f);
  case 12:
    return UINT32_C(0x35adf219);
  case 13:
    return UINT32_C(0xe14c679b);
  case 14:
    return UINT32_C(0x8a36bd05);
  case 15:
    return UINT32_C(0x5d9728d1);
  case 16:
    return UINT32_C(0xf03ba46b);
  case 17:
    return UINT32_C(0x28c5e719);
  case 18:
    return UINT32_C(0x9d610f53);
  case 19:
    return UINT32_C(0x467a32cd);
  case 20:
    return UINT32_C(0xb783d8a5);
  case 21:
    return UINT32_C(0x1ce94f87);
  case 22:
    return UINT32_C(0x72ad165b);
  case 23:
    return UINT32_C(0xcb508931);
  case 24:
    return UINT32_C(0x3f6cda97);
  case 25:
    return UINT32_C(0x84e1250b);
  case 26:
    return UINT32_C(0x1597bc6d);
  case 27:
    return UINT32_C(0xae42f803);
  case 28:
    return UINT32_C(0x61d30aef);
  case 29:
    return UINT32_C(0xd8b56c49);
  case 30:
    return UINT32_C(0x07fe9137);
  default:
    return UINT32_C(0x9a2845c1);
  }
#endif
}

static uint32_t large_switch_program(uint32_t seed) {
  return mix_word(large_switch_value(seed) ^ rotate_left(seed, 11u));
}
#endif

#if CONTROL_KIND == 2
static uint32_t interpreter_like_loop(uint32_t seed) {
  uint32_t accumulator = seed ^ UINT32_C(0x4f1bbcdc);
  uint32_t state = (seed >> 3) & 3u;
  uint32_t round;

  for (round = 0; round < 96u; ++round) {
    switch (state) {
    case 0:
      accumulator += rotate_left(seed ^ round, 3u);
      break;
    case 1:
      accumulator ^= rotate_left(accumulator + round, 7u);
      break;
    case 2:
      accumulator += UINT32_C(0x9e3779b9) ^ (round * 17u);
      break;
    default:
      accumulator = rotate_left(accumulator, 13u) ^ seed;
      break;
    }
    state = (state + ((accumulator >> (round & 7u)) & 3u) + 1u) & 3u;
  }

  return mix_word(accumulator ^ state);
}
#endif

#if CONTROL_KIND == 3
static uint32_t lookup_table_processor(uint32_t seed) {
  static const uint16_t lookup_words[64] = {
      0x2d5b, 0x1193, 0xe6a7, 0x73c1, 0x4f2e, 0x9ab8, 0x0c75, 0xd341,
      0x657c, 0xb829, 0x31e6, 0x8d54, 0xf207, 0x46ba, 0xac19, 0x5e83,
      0x7b2f, 0xc468, 0x18d5, 0x93ae, 0x2f41, 0xe879, 0x54c2, 0x0b96,
      0xd12c, 0x6fa3, 0xb547, 0x39d8, 0x84e1, 0x1a6d, 0xc073, 0x5bf4,
      0x27a9, 0x9c35, 0x40de, 0xf168, 0x6b02, 0xd794, 0x1eaf, 0x85c9,
      0x3d71, 0xa62b, 0x58f0, 0x0d4e, 0xce83, 0x7219, 0xb0d6, 0x49ac,
      0x94f2, 0x25b7, 0x7e4d, 0xdb10, 0x61c8, 0x0a36, 0xf58b, 0x4375,
      0x8ec1, 0x16da, 0xca67, 0x30b4, 0x79e0, 0xa15f, 0x4c28, 0xe392,
  };
  uint32_t value = seed;
  uint32_t index;

  for (index = 0; index < 64u; ++index) {
    uint32_t word = lookup_words[(seed + index * 13u) & 63u];
    value = rotate_left(value + word + index, (word >> 11) & 15u);
    value ^= word * UINT32_C(0x45d9f3b);
  }

  return mix_word(value);
}
#endif

#if CONTROL_KIND == 4
typedef uint32_t (*normal_step)(uint32_t value, uint32_t round);

static CONTROL_NOINLINE uint32_t normal_step_add(uint32_t value, uint32_t round) {
  return value + rotate_left(round + UINT32_C(0x9e3779b9), 5u);
}

static CONTROL_NOINLINE uint32_t normal_step_xor(uint32_t value, uint32_t round) {
  return value ^ rotate_left(value + round, 9u);
}

static CONTROL_NOINLINE uint32_t normal_step_mix(uint32_t value, uint32_t round) {
  return mix_word(value + round * UINT32_C(0x7f4a7c15));
}

static CONTROL_NOINLINE uint32_t normal_step_rotate(uint32_t value, uint32_t round) {
  return rotate_left(value ^ UINT32_C(0xa5a5a5a5), (round & 15u) + 1u);
}

static uint32_t dispatch_heavy_normal_code(uint32_t seed) {
  static normal_step const normal_steps[4] = {
      normal_step_add,
      normal_step_xor,
      normal_step_mix,
      normal_step_rotate,
  };
  uint32_t value = seed ^ UINT32_C(0x6d2b79f5);
  uint32_t round;

  for (round = 0; round < 48u; ++round) {
    normal_step step = normal_steps[(value ^ round) & 3u];
    value = step(value, round);
    value ^= rotate_left(seed + round, round & 7u);
  }

  return mix_word(value);
}
#endif

int main(int argc, char **argv) {
  uint32_t seed = (uint32_t)argc * UINT32_C(0x9e3779b9);
  seed ^= (uint32_t)((uintptr_t)argv >> 4);

#if CONTROL_KIND == 1
  return (int)(large_switch_program(seed) & 127u);
#elif CONTROL_KIND == 2
  return (int)(interpreter_like_loop(seed) & 127u);
#elif CONTROL_KIND == 3
  return (int)(lookup_table_processor(seed) & 127u);
#elif CONTROL_KIND == 4
  return (int)(dispatch_heavy_normal_code(seed) & 127u);
#else
#error "CONTROL_KIND must select a native control"
#endif
}
