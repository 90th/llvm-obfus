#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct ObfBlake2sState {
  uint32_t h[8];
  uint32_t t[2];
  uint32_t f[2];
  uint8_t buf[64];
  size_t buflen;
  size_t outlen;
};

struct ObfStringRuntimeDescriptorV1 {
  uint8_t *destination;
  const uint8_t *ciphertext;
  const uint8_t *build_key;
  uint32_t *state;
  uint64_t length;
  uint64_t module_id;
  uint64_t function_id;
  uint64_t site_id;
  uint32_t version;
  uint32_t flags;
  uint8_t nonce[16];
  uint8_t tag[16];
};

struct ObfConstantPoolRuntimeDescriptorV1 {
  uint8_t *destination;
  const uint8_t *ciphertext;
  const uint8_t *build_key;
  uint32_t *state;
  uint64_t length;
  uint64_t module_id;
  uint64_t pool_id;
  uint32_t version;
  uint32_t flags;
  uint8_t nonce[16];
  uint8_t tag[16];
};

enum {
  kObfBlake2sBlockBytes = 64,
  kObfBlake2sOutBytes = 32,
  kObfStringDescriptorVersionV1 = 1,
  kObfStringAuthFlagTrapOnFailure = 1u,
  kObfStringStateDecoded = 1u,
  kObfConstantPoolDescriptorVersionV1 = 1,
  kObfConstantPoolAuthFlagTrapOnFailure = 1u,
  kObfConstantPoolStateDecoded = 1u,
};

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

static const uint8_t kObfDomainFunction[2] = {'f', 'n'};
static const uint8_t kObfDomainString[6] = {'s', 't', 'r', 'i', 'n', 'g'};
static const uint8_t kObfDomainConstant[5] = {'c', 'o', 'n', 's', 't'};
static const uint8_t kObfDomainEnc[3] = {'e', 'n', 'c'};
static const uint8_t kObfDomainMac[3] = {'m', 'a', 'c'};
static const uint8_t kObfDomainStream[6] = {'s', 't', 'r', 'e', 'a', 'm'};
static const uint8_t kObfDomainStringTag[10] = {'s', 't', 'r', 'i', 'n', 'g', '_', 't', 'a', 'g'};
static const uint8_t kObfDomainConstantPoolTag[14] = {
    'c', 'o', 'n', 's', 't', '_', 'p', 'o', 'o', 'l', '_', 't', 'a', 'g'};

static uint32_t ObfLoad32(const uint8_t *input) {
  return (uint32_t)input[0] | ((uint32_t)input[1] << 8) | ((uint32_t)input[2] << 16) |
         ((uint32_t)input[3] << 24);
}

static void ObfStore32(uint32_t value, uint8_t *output) {
  output[0] = (uint8_t)value;
  output[1] = (uint8_t)(value >> 8);
  output[2] = (uint8_t)(value >> 16);
  output[3] = (uint8_t)(value >> 24);
}

static void ObfStore64(uint64_t value, uint8_t *output) {
  unsigned index;
  for (index = 0; index < 8; ++index) {
    output[index] = (uint8_t)(value >> (index * 8));
  }
}

static uint32_t ObfRotateRight(uint32_t value, unsigned amount) {
  return (value >> amount) | (value << (32u - amount));
}

static void ObfBlake2sMix(uint32_t v[16],
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

static void ObfBlake2sCompress(struct ObfBlake2sState *state, const uint8_t block[64]) {
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
}

static int ObfBlake2sInit(struct ObfBlake2sState *state, size_t output_size, const uint8_t *key, size_t key_size) {
  unsigned index;
  if (output_size == 0 || output_size > kObfBlake2sOutBytes || key_size > kObfBlake2sOutBytes) {
    return 0;
  }

  memset(state, 0, sizeof(*state));
  state->outlen = output_size;
  for (index = 0; index < 8; ++index) {
    state->h[index] = kObfBlake2sIv[index];
  }
  state->h[0] ^= 0x01010000u ^ ((uint32_t)key_size << 8) ^ (uint32_t)output_size;

  if (key != NULL && key_size != 0) {
    memcpy(state->buf, key, key_size);
    state->buflen = kObfBlake2sBlockBytes;
  }

  return 1;
}

static void ObfBlake2sIncrement(struct ObfBlake2sState *state, size_t count) {
  const uint32_t low = state->t[0] + (uint32_t)count;
  state->t[1] += (uint32_t)(low < state->t[0]);
  state->t[0] = low;
}

static void ObfBlake2sUpdate(struct ObfBlake2sState *state, const uint8_t *input, size_t input_size) {
  size_t offset = 0;
  if (input == NULL || input_size == 0) {
    return;
  }

  if (state->buflen == kObfBlake2sBlockBytes) {
    ObfBlake2sIncrement(state, kObfBlake2sBlockBytes);
    ObfBlake2sCompress(state, state->buf);
    memset(state->buf, 0, sizeof(state->buf));
    state->buflen = 0;
  }

  while (offset < input_size) {
    const size_t available = kObfBlake2sBlockBytes - state->buflen;
    const size_t remaining = input_size - offset;
    const size_t to_copy = available < remaining ? available : remaining;
    memcpy(state->buf + state->buflen, input + offset, to_copy);
    state->buflen += to_copy;
    offset += to_copy;

    if (state->buflen == kObfBlake2sBlockBytes && offset < input_size) {
      ObfBlake2sIncrement(state, kObfBlake2sBlockBytes);
      ObfBlake2sCompress(state, state->buf);
      memset(state->buf, 0, sizeof(state->buf));
      state->buflen = 0;
    }
  }
}

static void ObfBlake2sFinal(struct ObfBlake2sState *state, uint8_t output[32]) {
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
}

static void ObfBlake2sHash(uint8_t output[32],
                           const uint8_t *input,
                           size_t input_size,
                           const uint8_t *key,
                           size_t key_size) {
  struct ObfBlake2sState state;
  if (!ObfBlake2sInit(&state, 32, key, key_size)) {
    memset(output, 0, 32);
    return;
  }
  ObfBlake2sUpdate(&state, input, input_size);
  ObfBlake2sFinal(&state, output);
}

static void ObfBlake2sUpdateU32(struct ObfBlake2sState *state, uint32_t value) {
  uint8_t bytes[4];
  ObfStore32(value, bytes);
  ObfBlake2sUpdate(state, bytes, sizeof(bytes));
}

static void ObfBlake2sUpdateU64(struct ObfBlake2sState *state, uint64_t value) {
  uint8_t bytes[8];
  ObfStore64(value, bytes);
  ObfBlake2sUpdate(state, bytes, sizeof(bytes));
}

static void ObfBlake2sUpdateDomain(struct ObfBlake2sState *state, const uint8_t *domain, uint32_t domain_size) {
  ObfBlake2sUpdateU32(state, domain_size);
  ObfBlake2sUpdate(state, domain, domain_size);
}

static void ObfDeriveFunctionKey(uint8_t output[32], const uint8_t *build_key, uint64_t module_id, uint64_t function_id) {
  struct ObfBlake2sState state;
  ObfBlake2sInit(&state, 32, build_key, 32);
  ObfBlake2sUpdateDomain(&state, kObfDomainFunction, (uint32_t)sizeof(kObfDomainFunction));
  ObfBlake2sUpdateU64(&state, module_id);
  ObfBlake2sUpdateU64(&state, function_id);
  ObfBlake2sFinal(&state, output);
}

static void ObfDeriveSiteKey(uint8_t output[32], const uint8_t *function_key, const uint8_t *domain, uint32_t domain_size, uint64_t site_id) {
  struct ObfBlake2sState state;
  ObfBlake2sInit(&state, 32, function_key, 32);
  ObfBlake2sUpdateDomain(&state, domain, domain_size);
  ObfBlake2sUpdateU64(&state, site_id);
  ObfBlake2sFinal(&state, output);
}

static void ObfDeriveLabeledKey(uint8_t output[32], const uint8_t *key, const uint8_t *label, uint32_t label_size) {
  struct ObfBlake2sState state;
  ObfBlake2sInit(&state, 32, key, 32);
  ObfBlake2sUpdateDomain(&state, label, label_size);
  ObfBlake2sFinal(&state, output);
}

static void ObfMakeKeystreamBlock(uint8_t output[32], const uint8_t *enc_key, const uint8_t nonce[16], uint64_t counter) {
  struct ObfBlake2sState state;
  ObfBlake2sInit(&state, 32, enc_key, 32);
  ObfBlake2sUpdateDomain(&state, kObfDomainStream, (uint32_t)sizeof(kObfDomainStream));
  ObfBlake2sUpdate(&state, nonce, 16);
  ObfBlake2sUpdateU64(&state, counter);
  ObfBlake2sFinal(&state, output);
}

static void ObfComputeStringTag(uint8_t output[16],
                                const uint8_t *mac_key,
                                const struct ObfStringRuntimeDescriptorV1 *descriptor,
                                size_t ciphertext_size) {
  struct ObfBlake2sState state;
  uint8_t digest[32];
  ObfBlake2sInit(&state, 32, mac_key, 32);
  ObfBlake2sUpdateDomain(&state, kObfDomainStringTag, (uint32_t)sizeof(kObfDomainStringTag));
  ObfBlake2sUpdateU32(&state, descriptor->version);
  ObfBlake2sUpdateU32(&state, descriptor->flags);
  ObfBlake2sUpdateU64(&state, descriptor->length);
  ObfBlake2sUpdateU64(&state, descriptor->module_id);
  ObfBlake2sUpdateU64(&state, descriptor->function_id);
  ObfBlake2sUpdateU64(&state, descriptor->site_id);
  ObfBlake2sUpdate(&state, descriptor->nonce, sizeof(descriptor->nonce));
  ObfBlake2sUpdate(&state, descriptor->ciphertext, ciphertext_size);
  ObfBlake2sFinal(&state, digest);
  memcpy(output, digest, 16);
}

static void ObfComputeConstantPoolTag(uint8_t output[16],
                                      const uint8_t *mac_key,
                                      const struct ObfConstantPoolRuntimeDescriptorV1 *descriptor,
                                      size_t ciphertext_size) {
  struct ObfBlake2sState state;
  uint8_t digest[32];
  ObfBlake2sInit(&state, 32, mac_key, 32);
  ObfBlake2sUpdateDomain(&state,
                         kObfDomainConstantPoolTag,
                         (uint32_t)sizeof(kObfDomainConstantPoolTag));
  ObfBlake2sUpdateU32(&state, descriptor->version);
  ObfBlake2sUpdateU32(&state, descriptor->flags);
  ObfBlake2sUpdateU64(&state, descriptor->length);
  ObfBlake2sUpdateU64(&state, descriptor->module_id);
  ObfBlake2sUpdateU64(&state, descriptor->pool_id);
  ObfBlake2sUpdate(&state, descriptor->nonce, sizeof(descriptor->nonce));
  ObfBlake2sUpdate(&state, descriptor->ciphertext, ciphertext_size);
  ObfBlake2sFinal(&state, digest);
  memcpy(output, digest, 16);
}

static int ObfConstantTimeEqual(const uint8_t *lhs, const uint8_t *rhs, size_t size) {
  uint8_t diff = 0;
  size_t index;
  for (index = 0; index < size; ++index) {
    diff |= (uint8_t)(lhs[index] ^ rhs[index]);
  }
  return diff == 0;
}

static void ObfTrap(void) {
#if defined(__clang__) || defined(__GNUC__)
  __builtin_trap();
  __builtin_unreachable();
#else
  abort();
#endif
}

__attribute__((visibility("hidden")))
uint8_t *obf_string_auth_decode_v1(const struct ObfStringRuntimeDescriptorV1 *descriptor,
                                   uint64_t trusted_length) {
  uint8_t function_key[32];
  uint8_t site_key[32];
  uint8_t enc_key[32];
  uint8_t mac_key[32];
  uint8_t tag[16];
  size_t length;
  uint64_t offset = 0;
  uint64_t counter = 0;

  if (descriptor == NULL || descriptor->destination == NULL || descriptor->ciphertext == NULL ||
      descriptor->build_key == NULL || descriptor->state == NULL) {
    ObfTrap();
  }

  if (descriptor->version != kObfStringDescriptorVersionV1) {
    ObfTrap();
  }

  if (descriptor->flags != kObfStringAuthFlagTrapOnFailure) {
    ObfTrap();
  }

  if (descriptor->length != trusted_length || trusted_length > (uint64_t)SIZE_MAX) {
    ObfTrap();
  }
  length = (size_t)trusted_length;

  if (*descriptor->state == kObfStringStateDecoded) {
    return descriptor->destination;
  }

  if (*descriptor->state != 0u) {
    ObfTrap();
  }

  ObfDeriveFunctionKey(function_key, descriptor->build_key, descriptor->module_id, descriptor->function_id);
  ObfDeriveSiteKey(site_key,
                   function_key,
                   kObfDomainString,
                   (uint32_t)sizeof(kObfDomainString),
                   descriptor->site_id);
  ObfDeriveLabeledKey(enc_key, site_key, kObfDomainEnc, (uint32_t)sizeof(kObfDomainEnc));
  ObfDeriveLabeledKey(mac_key, site_key, kObfDomainMac, (uint32_t)sizeof(kObfDomainMac));
  ObfComputeStringTag(tag, mac_key, descriptor, length);
  if (!ObfConstantTimeEqual(tag, descriptor->tag, sizeof(tag))) {
    ObfTrap();
  }

  while (offset < trusted_length) {
    uint8_t block[32];
    size_t index;
    size_t block_size;
    ObfMakeKeystreamBlock(block, enc_key, descriptor->nonce, counter++);
    block_size = (size_t)(((trusted_length - offset) < sizeof(block)) ? (trusted_length - offset)
                                                                       : sizeof(block));
    for (index = 0; index < block_size; ++index) {
      descriptor->destination[offset + index] = (uint8_t)(descriptor->ciphertext[offset + index] ^ block[index]);
    }
    offset += block_size;
  }

  *descriptor->state = kObfStringStateDecoded;
  return descriptor->destination;
}

__attribute__((visibility("hidden")))
uint8_t *obf_constant_pool_decode_v1(const struct ObfConstantPoolRuntimeDescriptorV1 *descriptor,
                                     uint64_t trusted_length) {
  uint8_t function_key[32];
  uint8_t pool_key[32];
  uint8_t enc_key[32];
  uint8_t mac_key[32];
  uint8_t tag[16];
  size_t length;
  uint64_t offset = 0;
  uint64_t counter = 0;

  if (descriptor == NULL || descriptor->destination == NULL || descriptor->ciphertext == NULL ||
      descriptor->build_key == NULL || descriptor->state == NULL) {
    ObfTrap();
  }

  if (descriptor->version != kObfConstantPoolDescriptorVersionV1) {
    ObfTrap();
  }

  if (descriptor->flags != kObfConstantPoolAuthFlagTrapOnFailure) {
    ObfTrap();
  }

  if (descriptor->length != trusted_length || trusted_length > (uint64_t)SIZE_MAX) {
    ObfTrap();
  }
  length = (size_t)trusted_length;

  if (*descriptor->state == kObfConstantPoolStateDecoded) {
    return descriptor->destination;
  }

  if (*descriptor->state != 0u) {
    ObfTrap();
  }

  ObfDeriveFunctionKey(function_key, descriptor->build_key, descriptor->module_id, 0u);
  ObfDeriveSiteKey(pool_key,
                   function_key,
                   kObfDomainConstant,
                   (uint32_t)sizeof(kObfDomainConstant),
                   descriptor->pool_id);
  ObfDeriveLabeledKey(enc_key, pool_key, kObfDomainEnc, (uint32_t)sizeof(kObfDomainEnc));
  ObfDeriveLabeledKey(mac_key, pool_key, kObfDomainMac, (uint32_t)sizeof(kObfDomainMac));
  ObfComputeConstantPoolTag(tag, mac_key, descriptor, length);
  if (!ObfConstantTimeEqual(tag, descriptor->tag, sizeof(tag))) {
    ObfTrap();
  }

  while (offset < trusted_length) {
    uint8_t block[32];
    size_t index;
    size_t block_size;
    ObfMakeKeystreamBlock(block, enc_key, descriptor->nonce, counter++);
    block_size = (size_t)(((trusted_length - offset) < sizeof(block)) ? (trusted_length - offset)
                                                                       : sizeof(block));
    for (index = 0; index < block_size; ++index) {
      descriptor->destination[offset + index] =
          (uint8_t)(descriptor->ciphertext[offset + index] ^ block[index]);
    }
    offset += block_size;
  }

  *descriptor->state = kObfConstantPoolStateDecoded;
  return descriptor->destination;
}
