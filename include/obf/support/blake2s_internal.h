#pragma once

#include <stddef.h>
#include <stdint.h>

#ifndef OBF_NOINLINE
#if defined(__clang__) || defined(__GNUC__)
#define OBF_NOINLINE __attribute__((noinline, used))
#else
#define OBF_NOINLINE
#endif
#endif

enum {
  kObfBlake2sBlockBytes = 64,
  kObfBlake2sOutBytes = 32,
};

struct ObfBlake2sState {
  uint32_t h[8];
  uint32_t t[2];
  uint32_t f[2];
  uint8_t buf[64];
  size_t buflen;
  size_t outlen;
};

static inline OBF_NOINLINE void ObfSecureZeroize(void *buffer, size_t size) {
  volatile uint8_t *bytes = (volatile uint8_t *)buffer;
  while (size != 0) {
    *bytes = 0;
    ++bytes;
    --size;
  }
}

static inline void ObfBlake2sCopyBytes(uint8_t *dst, const uint8_t *src, size_t size) {
  size_t index;
  for (index = 0; index < size; ++index) {
    dst[index] = src[index];
  }
}

static const uint32_t kObfBlake2sIv[8] = {
    0x6a09e667u,
    0xbb67ae85u,
    0x3c6ef372u,
    0xa54ff53au,
    0x510e527fu,
    0x9b05688cu,
    0x1f83d9abu,
    0x5be0cd19u,
};

static const uint8_t kObfBlake2sSigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

static inline uint32_t ObfLoad32(const uint8_t *input) {
  return (uint32_t)input[0] | ((uint32_t)input[1] << 8) | ((uint32_t)input[2] << 16) |
         ((uint32_t)input[3] << 24);
}

static inline uint64_t ObfLoad64(const uint8_t *input) {
  uint64_t value = 0;
  unsigned index;
  for (index = 0; index < 8; ++index) {
    value |= (uint64_t)input[index] << (index * 8);
  }
  return value;
}

static inline void ObfStore32(uint32_t value, uint8_t *output) {
  output[0] = (uint8_t)value;
  output[1] = (uint8_t)(value >> 8);
  output[2] = (uint8_t)(value >> 16);
  output[3] = (uint8_t)(value >> 24);
}

static inline void ObfStore64(uint64_t value, uint8_t *output) {
  unsigned index;
  for (index = 0; index < 8; ++index) {
    output[index] = (uint8_t)(value >> (index * 8));
  }
}

static inline uint32_t ObfRotateRight(uint32_t value, unsigned amount) {
  return (value >> amount) | (value << (32u - amount));
}

static inline void ObfBlake2sMix(uint32_t v[16],
                                 unsigned a,
                                 unsigned b,
                                 unsigned c,
                                 unsigned d,
                                 uint32_t x,
                                 uint32_t y) {
  v[a] = v[a] + v[b] + x;
  v[d] = ObfRotateRight(v[d] ^ v[a], 16);
  v[c] = v[c] + v[d];
  v[b] = ObfRotateRight(v[b] ^ v[c], 12);
  v[a] = v[a] + v[b] + y;
  v[d] = ObfRotateRight(v[d] ^ v[a], 8);
  v[c] = v[c] + v[d];
  v[b] = ObfRotateRight(v[b] ^ v[c], 7);
}
static inline void ObfBlake2sCompress(struct ObfBlake2sState *state, const uint8_t block[64]) {
  uint32_t m[16];
  uint32_t v[16];
  unsigned index;
  unsigned round;

  for (index = 0; index < 16; ++index) {
    m[index] = ObfLoad32(block + (index * 4));
  }

  for (index = 0; index < 8; ++index) {
    v[index] = state->h[index];
    v[index + 8] = kObfBlake2sIv[index];
  }

  v[12] ^= state->t[0];
  v[13] ^= state->t[1];
  v[14] ^= state->f[0];
  v[15] ^= state->f[1];

  for (round = 0; round < 10; ++round) {
    const uint8_t *sigma = kObfBlake2sSigma[round];
    ObfBlake2sMix(v, 0, 4, 8, 12, m[sigma[0]], m[sigma[1]]);
    ObfBlake2sMix(v, 1, 5, 9, 13, m[sigma[2]], m[sigma[3]]);
    ObfBlake2sMix(v, 2, 6, 10, 14, m[sigma[4]], m[sigma[5]]);
    ObfBlake2sMix(v, 3, 7, 11, 15, m[sigma[6]], m[sigma[7]]);
    ObfBlake2sMix(v, 0, 5, 10, 15, m[sigma[8]], m[sigma[9]]);
    ObfBlake2sMix(v, 1, 6, 11, 12, m[sigma[10]], m[sigma[11]]);
    ObfBlake2sMix(v, 2, 7, 8, 13, m[sigma[12]], m[sigma[13]]);
    ObfBlake2sMix(v, 3, 4, 9, 14, m[sigma[14]], m[sigma[15]]);
  }

  for (index = 0; index < 8; ++index) {
    state->h[index] ^= v[index] ^ v[index + 8];
  }
  ObfSecureZeroize(m, sizeof(m));
  ObfSecureZeroize(v, sizeof(v));
}

static inline int ObfBlake2sInit(struct ObfBlake2sState *state,
                                 size_t output_size,
                                 const uint8_t *key,
                                 size_t key_size) {
  unsigned index;
  if (output_size == 0 || output_size > kObfBlake2sOutBytes || key_size > kObfBlake2sOutBytes) {
    return 0;
  }

  ObfSecureZeroize(state, sizeof(*state));
  state->outlen = output_size;
  for (index = 0; index < 8; ++index) {
    state->h[index] = kObfBlake2sIv[index];
  }
  state->h[0] ^= 0x01010000u ^ ((uint32_t)key_size << 8) ^ (uint32_t)output_size;

  if (key != NULL && key_size != 0) {
    ObfBlake2sCopyBytes(state->buf, key, key_size);
    state->buflen = kObfBlake2sBlockBytes;
  }

  return 1;
}

static inline void ObfBlake2sIncrement(struct ObfBlake2sState *state, size_t count) {
  const uint32_t low = state->t[0] + (uint32_t)count;
  state->t[1] += (uint32_t)(low < state->t[0]);
  state->t[0] = low;
}

static inline void ObfBlake2sUpdate(struct ObfBlake2sState *state,
                                    const uint8_t *input,
                                    size_t input_size) {
  size_t offset = 0;
  if (input == NULL || input_size == 0) {
    return;
  }

  if (state->buflen == kObfBlake2sBlockBytes) {
    ObfBlake2sIncrement(state, kObfBlake2sBlockBytes);
    ObfBlake2sCompress(state, state->buf);
    ObfSecureZeroize(state->buf, sizeof(state->buf));
    state->buflen = 0;
  }

  while (offset < input_size) {
    const size_t available = kObfBlake2sBlockBytes - state->buflen;
    const size_t remaining = input_size - offset;
    const size_t to_copy = available < remaining ? available : remaining;
    ObfBlake2sCopyBytes(state->buf + state->buflen, input + offset, to_copy);
    state->buflen += to_copy;
    offset += to_copy;

    if (state->buflen == kObfBlake2sBlockBytes && offset < input_size) {
      ObfBlake2sIncrement(state, kObfBlake2sBlockBytes);
      ObfBlake2sCompress(state, state->buf);
      ObfSecureZeroize(state->buf, sizeof(state->buf));
      state->buflen = 0;
    }
  }
}

static inline void ObfBlake2sFinal(struct ObfBlake2sState *state, uint8_t output[32]) {
  unsigned index;
  ObfBlake2sIncrement(state, state->buflen);
  state->f[0] = 0xffffffffu;
  for (index = (unsigned)state->buflen; index < kObfBlake2sBlockBytes; ++index) {
    state->buf[index] = 0;
  }
  ObfBlake2sCompress(state, state->buf);
  for (index = 0; index < 8; ++index) {
    ObfStore32(state->h[index], output + (index * 4));
  }
  ObfSecureZeroize(state, sizeof(*state));
}

static inline void ObfBlake2sUpdateU32(struct ObfBlake2sState *state, uint32_t value) {
  uint8_t bytes[4];
  ObfStore32(value, bytes);
  ObfBlake2sUpdate(state, bytes, sizeof(bytes));
  ObfSecureZeroize(bytes, sizeof(bytes));
}

static inline void ObfBlake2sUpdateU64(struct ObfBlake2sState *state, uint64_t value) {
  uint8_t bytes[8];
  ObfStore64(value, bytes);
  ObfBlake2sUpdate(state, bytes, sizeof(bytes));
  ObfSecureZeroize(bytes, sizeof(bytes));
}

static inline void ObfBlake2sUpdateDomain(struct ObfBlake2sState *state,
                                          const uint8_t *domain,
                                          uint32_t domain_size) {
  ObfBlake2sUpdateU32(state, domain_size);
  ObfBlake2sUpdate(state, domain, domain_size);
}
