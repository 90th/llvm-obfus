#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "obf/support/runtime_abi_generated.h"
#include "obf/support/runtime_atomic.h"

struct ObfBlake2sState {
  uint32_t h[8];
  uint32_t t[2];
  uint32_t f[2];
  uint8_t buf[64];
  size_t buflen;
  size_t outlen;
};

struct ObfAuthenticatedBufferReferenceV3 {
  uint64_t cookie;
  uint8_t *target;
};

struct ObfAuthenticatedStateReferenceV3 {
  uint64_t cookie;
  uint64_t status;
  uint64_t completion;
};

struct ObfAuthenticatedDecodeTopologyV3 {
  const void *descriptor;
  const struct ObfAuthenticatedBufferReferenceV3 *destination_ref;
  const uint8_t *destination_target;
  uint64_t destination_capacity;
  const struct ObfAuthenticatedBufferReferenceV3 *ciphertext_ref;
  const uint8_t *ciphertext_target;
  uint64_t ciphertext_capacity;
  const struct ObfAuthenticatedBufferReferenceV3 *build_key_ref;
  const uint8_t *build_key_target;
  uint64_t build_key_capacity;
  struct ObfAuthenticatedStateReferenceV3 *state_ref;
};

struct ObfStringRuntimeDescriptorV3 {
  uint32_t version;
  uint32_t flags;
  uint64_t length;
  uint64_t module_id;
  uint64_t function_id;
  uint64_t site_id;
  uint64_t binding_id;
  uint64_t destination_cookie;
  uint64_t ciphertext_cookie;
  uint64_t build_key_cookie;
  uint64_t state_cookie;
  uint64_t destination_capacity;
  uint64_t ciphertext_capacity;
  uint64_t build_key_capacity;
  uint8_t nonce[16];
  uint8_t tag[16];
  struct ObfAuthenticatedBufferReferenceV3 *destination;
  const struct ObfAuthenticatedBufferReferenceV3 *ciphertext;
  const struct ObfAuthenticatedBufferReferenceV3 *build_key;
  struct ObfAuthenticatedStateReferenceV3 *state;
};

struct ObfConstantPoolRuntimeDescriptorV3 {
  uint32_t version;
  uint32_t flags;
  uint64_t length;
  uint64_t module_id;
  uint64_t pool_id;
  uint64_t binding_id;
  uint64_t destination_cookie;
  uint64_t ciphertext_cookie;
  uint64_t build_key_cookie;
  uint64_t state_cookie;
  uint64_t destination_capacity;
  uint64_t ciphertext_capacity;
  uint64_t build_key_capacity;
  uint8_t nonce[16];
  uint8_t tag[16];
  struct ObfAuthenticatedBufferReferenceV3 *destination;
  const struct ObfAuthenticatedBufferReferenceV3 *ciphertext;
  const struct ObfAuthenticatedBufferReferenceV3 *build_key;
  struct ObfAuthenticatedStateReferenceV3 *state;
};

struct ObfCacheStatusSet {
  uint64_t cold;
  uint64_t decoding;
  uint64_t decoded;
};

struct ObfStringValidationContext {
  uint8_t *destination;
  const uint8_t *ciphertext;
  const uint8_t *build_key;
  size_t length;
  uint8_t enc_key[32];
  uint8_t mac_key[32];
  struct ObfCacheStatusSet statuses;
};

struct ObfConstantPoolValidationContext {
  uint8_t *destination;
  const uint8_t *ciphertext;
  const uint8_t *build_key;
  size_t length;
  uint8_t enc_key[32];
  uint8_t mac_key[32];
  struct ObfCacheStatusSet statuses;
};

enum {
  kObfBlake2sBlockBytes = 64,
  kObfBlake2sOutBytes = 32,
  kObfBuildKeyBytes = 32,
  kObfStringDescriptorVersionV3 = 3,
  kObfStringAuthFlagTrapOnFailure = 1u,
  kObfConstantPoolDescriptorVersionV3 = 3,
  kObfConstantPoolAuthFlagTrapOnFailure = 1u,
  kObfAuthDescriptorKindString = 1u,
  kObfAuthDescriptorKindConstantPool = 2u,
  kObfAuthReferenceRoleDestination = 1u,
  kObfAuthReferenceRoleCiphertext = 2u,
  kObfAuthReferenceRoleBuildKey = 3u,
  kObfAuthReferenceRoleState = 4u,
  kObfCacheStatusCold = 0u,
  kObfCacheStatusDecoding = 1u,
  kObfCacheStatusDecoded = 2u,
  kObfDecodePollLimit = 1u << 20,
};

#define OBF_MAX_SIZE(lhs, rhs) ((lhs) < (rhs) ? (rhs) : (lhs))
#define OBF_ROUND_UP_SIZE(value, alignment) \
  (((value) + (alignment) - 1) / (alignment) * (alignment))

_Static_assert(offsetof(struct ObfAuthenticatedBufferReferenceV3, cookie) == 0,
               "buffer reference cookie offset");
_Static_assert(offsetof(struct ObfAuthenticatedBufferReferenceV3, target) == 8,
               "buffer reference target offset");
_Static_assert(sizeof(struct ObfAuthenticatedBufferReferenceV3) == 16,
               "buffer reference size");
_Static_assert(_Alignof(struct ObfAuthenticatedBufferReferenceV3) == 8,
               "buffer reference alignment");
_Static_assert(offsetof(struct ObfAuthenticatedStateReferenceV3, cookie) == 0,
               "state reference cookie offset");
_Static_assert(offsetof(struct ObfAuthenticatedStateReferenceV3, status) == 8,
               "state reference status offset");
_Static_assert(offsetof(struct ObfAuthenticatedStateReferenceV3, completion) == 16,
               "state reference completion offset");
_Static_assert(sizeof(struct ObfAuthenticatedStateReferenceV3) == 24,
               "state reference size");
_Static_assert(_Alignof(struct ObfAuthenticatedStateReferenceV3) == 8,
               "state reference alignment");

#define OBF_ASSERT_STRING_FIELD(field, offset) \
  _Static_assert(offsetof(struct ObfStringRuntimeDescriptorV3, field) == (offset), \
                 "string descriptor field offset")
#define OBF_ASSERT_POOL_FIELD(field, offset) \
  _Static_assert(offsetof(struct ObfConstantPoolRuntimeDescriptorV3, field) == (offset), \
                 "constant pool descriptor field offset")
OBF_ASSERT_STRING_FIELD(version, 0);
OBF_ASSERT_STRING_FIELD(flags, 4);
OBF_ASSERT_STRING_FIELD(length, 8);
OBF_ASSERT_STRING_FIELD(module_id, 16);
OBF_ASSERT_STRING_FIELD(function_id, 24);
OBF_ASSERT_STRING_FIELD(site_id, 32);
OBF_ASSERT_STRING_FIELD(binding_id, 40);
OBF_ASSERT_STRING_FIELD(destination_cookie, 48);
OBF_ASSERT_STRING_FIELD(ciphertext_cookie, 56);
OBF_ASSERT_STRING_FIELD(build_key_cookie, 64);
OBF_ASSERT_STRING_FIELD(state_cookie, 72);
OBF_ASSERT_STRING_FIELD(destination_capacity, 80);
OBF_ASSERT_STRING_FIELD(ciphertext_capacity, 88);
OBF_ASSERT_STRING_FIELD(build_key_capacity, 96);
OBF_ASSERT_STRING_FIELD(nonce, 104);
OBF_ASSERT_STRING_FIELD(tag, 120);
OBF_ASSERT_STRING_FIELD(destination, 136);
OBF_ASSERT_STRING_FIELD(ciphertext, 144);
OBF_ASSERT_STRING_FIELD(build_key, 152);
OBF_ASSERT_STRING_FIELD(state, 160);
OBF_ASSERT_POOL_FIELD(version, 0);
OBF_ASSERT_POOL_FIELD(flags, 4);
OBF_ASSERT_POOL_FIELD(length, 8);
OBF_ASSERT_POOL_FIELD(module_id, 16);
OBF_ASSERT_POOL_FIELD(pool_id, 24);
OBF_ASSERT_POOL_FIELD(binding_id, 32);
OBF_ASSERT_POOL_FIELD(destination_cookie, 40);
OBF_ASSERT_POOL_FIELD(ciphertext_cookie, 48);
OBF_ASSERT_POOL_FIELD(build_key_cookie, 56);
OBF_ASSERT_POOL_FIELD(state_cookie, 64);
OBF_ASSERT_POOL_FIELD(destination_capacity, 72);
OBF_ASSERT_POOL_FIELD(ciphertext_capacity, 80);
OBF_ASSERT_POOL_FIELD(build_key_capacity, 88);
OBF_ASSERT_POOL_FIELD(nonce, 96);
OBF_ASSERT_POOL_FIELD(tag, 112);
OBF_ASSERT_POOL_FIELD(destination, 128);
OBF_ASSERT_POOL_FIELD(ciphertext, 136);
OBF_ASSERT_POOL_FIELD(build_key, 144);
OBF_ASSERT_POOL_FIELD(state, 152);
_Static_assert(sizeof(struct ObfStringRuntimeDescriptorV3) == 168,
               "string descriptor size");
_Static_assert(_Alignof(struct ObfStringRuntimeDescriptorV3) == 8,
               "string descriptor alignment");
_Static_assert(sizeof(struct ObfConstantPoolRuntimeDescriptorV3) == 160,
               "constant pool descriptor size");
_Static_assert(_Alignof(struct ObfConstantPoolRuntimeDescriptorV3) == 8,
               "constant pool descriptor alignment");

#define OBF_ASSERT_TOPO_FIELD(field, offset) \
  _Static_assert(offsetof(struct ObfAuthenticatedDecodeTopologyV3, field) == (offset), \
                 "decode topology field offset")
OBF_ASSERT_TOPO_FIELD(descriptor, 0);
OBF_ASSERT_TOPO_FIELD(destination_ref, 8);
OBF_ASSERT_TOPO_FIELD(destination_target, 16);
OBF_ASSERT_TOPO_FIELD(destination_capacity, 24);
OBF_ASSERT_TOPO_FIELD(ciphertext_ref, 32);
OBF_ASSERT_TOPO_FIELD(ciphertext_target, 40);
OBF_ASSERT_TOPO_FIELD(ciphertext_capacity, 48);
OBF_ASSERT_TOPO_FIELD(build_key_ref, 56);
OBF_ASSERT_TOPO_FIELD(build_key_target, 64);
OBF_ASSERT_TOPO_FIELD(build_key_capacity, 72);
OBF_ASSERT_TOPO_FIELD(state_ref, 80);
_Static_assert(sizeof(struct ObfAuthenticatedDecodeTopologyV3) == 88,
               "decode topology size");
_Static_assert(_Alignof(struct ObfAuthenticatedDecodeTopologyV3) == 8,
               "decode topology alignment");

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
static const uint8_t kObfDomainStringTagV3[13] = {
    's', 't', 'r', 'i', 'n', 'g', '_', 't', 'a', 'g', '_', 'v', '3'};
static const uint8_t kObfDomainConstantPoolTagV3[17] = {
    'c', 'o', 'n', 's', 't', '_', 'p', 'o', 'o', 'l', '_', 't', 'a', 'g', '_', 'v', '3'};
static const uint8_t kObfDomainStringBindingV3[17] = {
    's', 't', 'r', 'i', 'n', 'g', '_', 'b', 'i', 'n', 'd', 'i', 'n', 'g', '_', 'v', '3'};
static const uint8_t kObfDomainConstantBindingV3[19] = {
    'c', 'o', 'n', 's', 't', 'a', 'n', 't', '_', 'b', 'i', 'n', 'd', 'i', 'n', 'g', '_', 'v', '3'};
static const uint8_t kObfDomainReferenceCookieV3[19] = {
    'r', 'e', 'f', 'e', 'r', 'e', 'n', 'c', 'e', '_', 'c', 'o', 'o', 'k', 'i', 'e', '_', 'v', '3'};
static const uint8_t kObfDomainBuildKeyCookieV3[19] = {
    'b', 'u', 'i', 'l', 'd', '_', 'k', 'e', 'y', '_', 'c', 'o', 'o', 'k', 'i', 'e', '_', 'v', '3'};
static const uint8_t kObfDomainCacheStatusV3[15] = {
    'c', 'a', 'c', 'h', 'e', '_', 's', 't', 'a', 't', 'u', 's', '_', 'v', '3'};
static const uint8_t kObfDomainRuntimeStateTokenV3[22] = {
    'r', 'u', 'n', 't', 'i', 'm', 'e', '_', 's', 't', 'a', 't', 'e', '_', 't', 'o', 'k', 'e', 'n', '_', 'v', '3'};
static const uint8_t kObfDomainDecodedCompletionV3[21] = {
    'd', 'e', 'c', 'o', 'd', 'e', 'd', '_', 'c', 'o', 'm', 'p', 'l', 'e', 't', 'i', 'o', 'n', '_', 'v', '3'};

static uint32_t ObfLoad32(const uint8_t *input) {
  return (uint32_t)input[0] | ((uint32_t)input[1] << 8) | ((uint32_t)input[2] << 16) |
         ((uint32_t)input[3] << 24);
}

static uint64_t ObfLoad64(const uint8_t *input) {
  uint64_t value = 0;
  unsigned index;
  for (index = 0; index < 8; ++index) {
    value |= (uint64_t)input[index] << (index * 8);
  }
  return value;
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

static int ObfBlake2sInit(struct ObfBlake2sState *state,
                          size_t output_size,
                          const uint8_t *key,
                          size_t key_size) {
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

static void ObfBlake2sUpdate(struct ObfBlake2sState *state,
                             const uint8_t *input,
                             size_t input_size) {
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

static void ObfBlake2sUpdateDomain(struct ObfBlake2sState *state,
                                   const uint8_t *domain,
                                   uint32_t domain_size) {
  ObfBlake2sUpdateU32(state, domain_size);
  ObfBlake2sUpdate(state, domain, domain_size);
}

static uint64_t ObfMakeDerivedNonzeroFallback(uint64_t binding_id, uint64_t selector) {
  return (0x9e3779b97f4a7c15ULL ^ binding_id ^ (selector << 32)) | 1ULL;
}

static uint64_t ObfFinalizeDerivedWord(struct ObfBlake2sState *state,
                                       uint64_t binding_id,
                                       uint64_t selector) {
  uint8_t digest[32];
  const uint64_t value = (ObfBlake2sFinal(state, digest), ObfLoad64(digest));
  return value == 0 ? ObfMakeDerivedNonzeroFallback(binding_id, selector) : value;
}

static uint64_t ObfNormalizeDerivedWord(uint64_t value,
                                        uint64_t binding_id,
                                        uint64_t selector) {
  return value == 0 ? ObfMakeDerivedNonzeroFallback(binding_id, selector) : value;
}

static uint64_t ObfDeriveStringBindingId(uint64_t module_id,
                                         uint64_t function_id,
                                         uint64_t site_id) {
  struct ObfBlake2sState state;
  ObfBlake2sInit(&state, 32, NULL, 0);
  ObfBlake2sUpdateDomain(&state,
                         kObfDomainStringBindingV3,
                         (uint32_t)sizeof(kObfDomainStringBindingV3));
  ObfBlake2sUpdateU64(&state, module_id);
  ObfBlake2sUpdateU64(&state, function_id);
  ObfBlake2sUpdateU64(&state, site_id);
  return ObfFinalizeDerivedWord(&state, module_id ^ function_id, site_id);
}

static uint64_t ObfDeriveConstantPoolBindingId(uint64_t module_id, uint64_t pool_id) {
  struct ObfBlake2sState state;
  ObfBlake2sInit(&state, 32, NULL, 0);
  ObfBlake2sUpdateDomain(&state,
                         kObfDomainConstantBindingV3,
                         (uint32_t)sizeof(kObfDomainConstantBindingV3));
  ObfBlake2sUpdateU64(&state, module_id);
  ObfBlake2sUpdateU64(&state, pool_id);
  return ObfFinalizeDerivedWord(&state, module_id, pool_id);
}

static uint64_t ObfDeriveReferenceCookie(const uint8_t *mac_key,
                                         uint32_t descriptor_kind,
                                         uint64_t binding_id,
                                         uint32_t role,
                                         uint64_t capacity) {
  struct ObfBlake2sState state;
  ObfBlake2sInit(&state, 32, mac_key, 32);
  ObfBlake2sUpdateDomain(&state,
                         kObfDomainReferenceCookieV3,
                         (uint32_t)sizeof(kObfDomainReferenceCookieV3));
  ObfBlake2sUpdateU32(&state, descriptor_kind);
  ObfBlake2sUpdateU64(&state, binding_id);
  ObfBlake2sUpdateU32(&state, role);
  ObfBlake2sUpdateU64(&state, capacity);
  return ObfFinalizeDerivedWord(&state, binding_id ^ capacity, role);
}

static uint64_t ObfDeriveBuildKeyCookie(const uint8_t *build_key,
                                        uint32_t descriptor_kind,
                                        uint64_t binding_id,
                                        uint64_t capacity) {
  struct ObfBlake2sState state;
  ObfBlake2sInit(&state, 32, build_key, kObfBuildKeyBytes);
  ObfBlake2sUpdateDomain(&state,
                         kObfDomainBuildKeyCookieV3,
                         (uint32_t)sizeof(kObfDomainBuildKeyCookieV3));
  ObfBlake2sUpdateU32(&state, descriptor_kind);
  ObfBlake2sUpdateU64(&state, binding_id);
  ObfBlake2sUpdateU32(&state, kObfAuthReferenceRoleBuildKey);
  ObfBlake2sUpdateU64(&state, capacity);
  return ObfFinalizeDerivedWord(&state, binding_id ^ capacity, kObfAuthReferenceRoleBuildKey);
}

static uint64_t ObfDeriveCacheColdStatus(const uint8_t *mac_key,
                                         uint32_t descriptor_kind,
                                         uint64_t binding_id,
                                         uint64_t destination_capacity,
                                         uint64_t ciphertext_capacity,
                                         uint64_t build_key_capacity) {
  struct ObfBlake2sState state;
  ObfBlake2sInit(&state, 32, mac_key, 32);
  ObfBlake2sUpdateDomain(&state,
                         kObfDomainCacheStatusV3,
                         (uint32_t)sizeof(kObfDomainCacheStatusV3));
  ObfBlake2sUpdateU32(&state, descriptor_kind);
  ObfBlake2sUpdateU64(&state, binding_id);
  ObfBlake2sUpdateU64(&state, destination_capacity);
  ObfBlake2sUpdateU64(&state, ciphertext_capacity);
  ObfBlake2sUpdateU64(&state, build_key_capacity);
  ObfBlake2sUpdateU32(&state, kObfCacheStatusCold);
  return ObfFinalizeDerivedWord(&state,
                                binding_id ^ destination_capacity,
                                kObfCacheStatusCold);
}

static void ObfDeriveFunctionKey(uint8_t output[32],
                                 const uint8_t *build_key,
                                 uint64_t module_id,
                                 uint64_t function_id) {
  struct ObfBlake2sState state;
  ObfBlake2sInit(&state, 32, build_key, kObfBuildKeyBytes);
  ObfBlake2sUpdateDomain(&state, kObfDomainFunction, (uint32_t)sizeof(kObfDomainFunction));
  ObfBlake2sUpdateU64(&state, module_id);
  ObfBlake2sUpdateU64(&state, function_id);
  ObfBlake2sFinal(&state, output);
}

static void ObfDeriveSiteKey(uint8_t output[32],
                             const uint8_t *function_key,
                             const uint8_t *domain,
                             uint32_t domain_size,
                             uint64_t site_id) {
  struct ObfBlake2sState state;
  ObfBlake2sInit(&state, 32, function_key, 32);
  ObfBlake2sUpdateDomain(&state, domain, domain_size);
  ObfBlake2sUpdateU64(&state, site_id);
  ObfBlake2sFinal(&state, output);
}

static void ObfDeriveLabeledKey(uint8_t output[32],
                                const uint8_t *key,
                                const uint8_t *label,
                                uint32_t label_size) {
  struct ObfBlake2sState state;
  ObfBlake2sInit(&state, 32, key, 32);
  ObfBlake2sUpdateDomain(&state, label, label_size);
  ObfBlake2sFinal(&state, output);
}

static void ObfMakeKeystreamBlock(uint8_t output[32],
                                  const uint8_t *enc_key,
                                  const uint8_t nonce[16],
                                  uint64_t counter) {
  struct ObfBlake2sState state;
  ObfBlake2sInit(&state, 32, enc_key, 32);
  ObfBlake2sUpdateDomain(&state, kObfDomainStream, (uint32_t)sizeof(kObfDomainStream));
  ObfBlake2sUpdate(&state, nonce, 16);
  ObfBlake2sUpdateU64(&state, counter);
  ObfBlake2sFinal(&state, output);
}

static void ObfComputeStringTag(uint8_t output[16],
                                const uint8_t *mac_key,
                                const struct ObfStringRuntimeDescriptorV3 *descriptor,
                                const uint8_t *ciphertext,
                                size_t ciphertext_size) {
  struct ObfBlake2sState state;
  uint8_t digest[32];
  ObfBlake2sInit(&state, 32, mac_key, 32);
  ObfBlake2sUpdateDomain(
      &state, kObfDomainStringTagV3, (uint32_t)sizeof(kObfDomainStringTagV3));
  ObfBlake2sUpdateU32(&state, descriptor->version);
  ObfBlake2sUpdateU32(&state, descriptor->flags);
  ObfBlake2sUpdateU64(&state, descriptor->length);
  ObfBlake2sUpdateU64(&state, descriptor->module_id);
  ObfBlake2sUpdateU64(&state, descriptor->function_id);
  ObfBlake2sUpdateU64(&state, descriptor->site_id);
  ObfBlake2sUpdateU64(&state, descriptor->binding_id);
  ObfBlake2sUpdateU64(&state, descriptor->destination_cookie);
  ObfBlake2sUpdateU64(&state, descriptor->ciphertext_cookie);
  ObfBlake2sUpdateU64(&state, descriptor->build_key_cookie);
  ObfBlake2sUpdateU64(&state, descriptor->state_cookie);
  ObfBlake2sUpdateU64(&state, descriptor->destination_capacity);
  ObfBlake2sUpdateU64(&state, descriptor->ciphertext_capacity);
  ObfBlake2sUpdateU64(&state, descriptor->build_key_capacity);
  ObfBlake2sUpdate(&state, descriptor->nonce, sizeof(descriptor->nonce));
  ObfBlake2sUpdate(&state, ciphertext, ciphertext_size);
  ObfBlake2sFinal(&state, digest);
  memcpy(output, digest, 16);
}

static void ObfComputeConstantPoolTag(
    uint8_t output[16],
    const uint8_t *mac_key,
    const struct ObfConstantPoolRuntimeDescriptorV3 *descriptor,
    const uint8_t *ciphertext,
    size_t ciphertext_size) {
  struct ObfBlake2sState state;
  uint8_t digest[32];
  ObfBlake2sInit(&state, 32, mac_key, 32);
  ObfBlake2sUpdateDomain(&state,
                         kObfDomainConstantPoolTagV3,
                         (uint32_t)sizeof(kObfDomainConstantPoolTagV3));
  ObfBlake2sUpdateU32(&state, descriptor->version);
  ObfBlake2sUpdateU32(&state, descriptor->flags);
  ObfBlake2sUpdateU64(&state, descriptor->length);
  ObfBlake2sUpdateU64(&state, descriptor->module_id);
  ObfBlake2sUpdateU64(&state, descriptor->pool_id);
  ObfBlake2sUpdateU64(&state, descriptor->binding_id);
  ObfBlake2sUpdateU64(&state, descriptor->destination_cookie);
  ObfBlake2sUpdateU64(&state, descriptor->ciphertext_cookie);
  ObfBlake2sUpdateU64(&state, descriptor->build_key_cookie);
  ObfBlake2sUpdateU64(&state, descriptor->state_cookie);
  ObfBlake2sUpdateU64(&state, descriptor->destination_capacity);
  ObfBlake2sUpdateU64(&state, descriptor->ciphertext_capacity);
  ObfBlake2sUpdateU64(&state, descriptor->build_key_capacity);
  ObfBlake2sUpdate(&state, descriptor->nonce, sizeof(descriptor->nonce));
  ObfBlake2sUpdate(&state, ciphertext, ciphertext_size);
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

static void ObfDecodePayload(uint8_t *destination,
                             const uint8_t *ciphertext,
                             const uint8_t *enc_key,
                             const uint8_t nonce[16],
                             size_t length) {
  size_t offset = 0;
  uint64_t counter = 0;
  while (offset < length) {
    uint8_t block[32];
    size_t index;
    size_t block_size;
    ObfMakeKeystreamBlock(block, enc_key, nonce, counter++);
    block_size = (length - offset) < sizeof(block) ? (length - offset) : sizeof(block);
    for (index = 0; index < block_size; ++index) {
      destination[offset + index] = (uint8_t)(ciphertext[offset + index] ^ block[index]);
    }
    offset += block_size;
  }
}


static uint64_t ObfDeriveRuntimeStateTokenKeyed(const uint8_t *mac_key,
                                                uint32_t descriptor_kind,
                                                uint64_t binding_id,
                                                const void *descriptor,
                                                const void *topology,
                                                const void *state_ref,
                                                uint32_t phase) {
  struct ObfBlake2sState state;
  ObfBlake2sInit(&state, 32, mac_key, 32);
  ObfBlake2sUpdateDomain(&state,
                         kObfDomainRuntimeStateTokenV3,
                         (uint32_t)sizeof(kObfDomainRuntimeStateTokenV3));
  ObfBlake2sUpdateU32(&state, descriptor_kind);
  ObfBlake2sUpdateU64(&state, binding_id);
  ObfBlake2sUpdateU64(&state, (uint64_t)(uintptr_t)descriptor);
  ObfBlake2sUpdateU64(&state, (uint64_t)(uintptr_t)topology);
  ObfBlake2sUpdateU64(&state, (uint64_t)(uintptr_t)state_ref);
  ObfBlake2sUpdateU32(&state, phase);
  return ObfFinalizeDerivedWord(&state, binding_id, phase);
}

static void ObfDeriveRelocationStatuses(struct ObfCacheStatusSet *statuses,
                                        const uint8_t *mac_key,
                                        uint32_t descriptor_kind,
                                        uint64_t binding_id,
                                        const void *descriptor,
                                        const void *topology,
                                        const void *state_ref) {
  statuses->decoding = ObfDeriveRuntimeStateTokenKeyed(mac_key,
                                                        descriptor_kind,
                                                        binding_id,
                                                        descriptor,
                                                        topology,
                                                        state_ref,
                                                        kObfCacheStatusDecoding);
  statuses->decoded = ObfDeriveRuntimeStateTokenKeyed(mac_key,
                                                       descriptor_kind,
                                                       binding_id,
                                                       descriptor,
                                                       topology,
                                                       state_ref,
                                                       kObfCacheStatusDecoded);
  if (statuses->decoding == 0 || statuses->decoded == 0 ||
      statuses->decoding == statuses->cold || statuses->decoded == statuses->cold ||
      statuses->decoding == statuses->decoded) {
    ObfTrap();
  }
}

static void ObfValidateStringDescriptor(
    struct ObfStringValidationContext *context,
    const struct ObfStringRuntimeDescriptorV3 *descriptor,
    uint64_t trusted_length,
    uint64_t trusted_binding,
    const struct ObfAuthenticatedDecodeTopologyV3 *topology) {
  uint8_t function_key[32];
  uint8_t site_key[32];
  uint64_t derived_binding;
  uint64_t expected_build_key_cookie;
  uint64_t destination_cookie;
  uint64_t ciphertext_cookie;
  uint64_t state_cookie;

  if (descriptor == NULL || topology == NULL || topology->descriptor == NULL ||
      topology->destination_ref == NULL || topology->destination_target == NULL ||
      topology->ciphertext_ref == NULL || topology->ciphertext_target == NULL ||
      topology->build_key_ref == NULL || topology->build_key_target == NULL ||
      topology->state_ref == NULL) {
    ObfTrap();
  }
  if (topology->descriptor != descriptor) {
    ObfTrap();
  }
  if (descriptor->destination == NULL || descriptor->ciphertext == NULL ||
      descriptor->build_key == NULL || descriptor->state == NULL) {
    ObfTrap();
  }
  if (descriptor->destination != topology->destination_ref ||
      descriptor->ciphertext != topology->ciphertext_ref ||
      descriptor->build_key != topology->build_key_ref ||
      descriptor->state != topology->state_ref ||
      descriptor->destination->target != topology->destination_target ||
      descriptor->ciphertext->target != topology->ciphertext_target ||
      descriptor->build_key->target != topology->build_key_target) {
    ObfTrap();
  }
  if (descriptor->destination_capacity != topology->destination_capacity ||
      descriptor->ciphertext_capacity != topology->ciphertext_capacity ||
      descriptor->build_key_capacity != topology->build_key_capacity ||
      trusted_length > topology->destination_capacity ||
      trusted_length > topology->ciphertext_capacity ||
      topology->build_key_capacity != kObfBuildKeyBytes) {
    ObfTrap();
  }
  if (descriptor->version != kObfStringDescriptorVersionV3 ||
      descriptor->flags != kObfStringAuthFlagTrapOnFailure ||
      descriptor->length != trusted_length || trusted_length > (uint64_t)SIZE_MAX) {
    ObfTrap();
  }

  derived_binding =
      ObfDeriveStringBindingId(descriptor->module_id, descriptor->function_id, descriptor->site_id);
  if (descriptor->binding_id != trusted_binding || descriptor->binding_id != derived_binding) {
    ObfTrap();
  }

  context->destination = descriptor->destination->target;
  context->ciphertext = descriptor->ciphertext->target;
  context->build_key = descriptor->build_key->target;
  context->length = (size_t)trusted_length;
  ObfDeriveFunctionKey(
      function_key, context->build_key, descriptor->module_id, descriptor->function_id);
  ObfDeriveSiteKey(site_key,
                   function_key,
                   kObfDomainString,
                   (uint32_t)sizeof(kObfDomainString),
                   descriptor->site_id);
  ObfDeriveLabeledKey(
      context->enc_key, site_key, kObfDomainEnc, (uint32_t)sizeof(kObfDomainEnc));
  ObfDeriveLabeledKey(
      context->mac_key, site_key, kObfDomainMac, (uint32_t)sizeof(kObfDomainMac));

  expected_build_key_cookie = ObfDeriveBuildKeyCookie(
      context->build_key, kObfAuthDescriptorKindString, descriptor->binding_id, 32);
  destination_cookie = ObfDeriveReferenceCookie(context->mac_key,
                                                kObfAuthDescriptorKindString,
                                                descriptor->binding_id,
                                                kObfAuthReferenceRoleDestination,
                                                descriptor->destination_capacity);
  ciphertext_cookie = ObfDeriveReferenceCookie(context->mac_key,
                                                kObfAuthDescriptorKindString,
                                                descriptor->binding_id,
                                                kObfAuthReferenceRoleCiphertext,
                                                descriptor->ciphertext_capacity);
  state_cookie = ObfDeriveReferenceCookie(context->mac_key,
                                          kObfAuthDescriptorKindString,
                                          descriptor->binding_id,
                                          kObfAuthReferenceRoleState,
                                          0);
  if (descriptor->destination_cookie != destination_cookie ||
      descriptor->destination->cookie != destination_cookie ||
      descriptor->ciphertext_cookie != ciphertext_cookie ||
      descriptor->ciphertext->cookie != ciphertext_cookie ||
      descriptor->build_key_cookie != expected_build_key_cookie ||
      descriptor->build_key->cookie != expected_build_key_cookie ||
      descriptor->state_cookie != state_cookie || descriptor->state->cookie != state_cookie) {
    ObfTrap();
  }
  context->statuses.cold = ObfDeriveCacheColdStatus(context->mac_key,
                                                    kObfAuthDescriptorKindString,
                                                    descriptor->binding_id,
                                                    descriptor->destination_capacity,
                                                    descriptor->ciphertext_capacity,
                                                    descriptor->build_key_capacity);
}

static void ObfValidateConstantPoolDescriptor(
    struct ObfConstantPoolValidationContext *context,
    const struct ObfConstantPoolRuntimeDescriptorV3 *descriptor,
    uint64_t trusted_length,
    uint64_t trusted_binding,
    const struct ObfAuthenticatedDecodeTopologyV3 *topology) {
  uint8_t function_key[32];
  uint8_t pool_key[32];
  uint64_t derived_binding;
  uint64_t expected_build_key_cookie;
  uint64_t destination_cookie;
  uint64_t ciphertext_cookie;
  uint64_t state_cookie;

  if (descriptor == NULL || topology == NULL || topology->descriptor == NULL ||
      topology->destination_ref == NULL || topology->destination_target == NULL ||
      topology->ciphertext_ref == NULL || topology->ciphertext_target == NULL ||
      topology->build_key_ref == NULL || topology->build_key_target == NULL ||
      topology->state_ref == NULL) {
    ObfTrap();
  }
  if (topology->descriptor != descriptor) {
    ObfTrap();
  }
  if (descriptor->destination == NULL || descriptor->ciphertext == NULL ||
      descriptor->build_key == NULL || descriptor->state == NULL) {
    ObfTrap();
  }
  if (descriptor->destination != topology->destination_ref ||
      descriptor->ciphertext != topology->ciphertext_ref ||
      descriptor->build_key != topology->build_key_ref ||
      descriptor->state != topology->state_ref ||
      descriptor->destination->target != topology->destination_target ||
      descriptor->ciphertext->target != topology->ciphertext_target ||
      descriptor->build_key->target != topology->build_key_target) {
    ObfTrap();
  }
  if (descriptor->destination_capacity != topology->destination_capacity ||
      descriptor->ciphertext_capacity != topology->ciphertext_capacity ||
      descriptor->build_key_capacity != topology->build_key_capacity ||
      trusted_length > topology->destination_capacity ||
      trusted_length > topology->ciphertext_capacity ||
      topology->build_key_capacity != kObfBuildKeyBytes) {
    ObfTrap();
  }
  if (descriptor->version != kObfConstantPoolDescriptorVersionV3 ||
      descriptor->flags != kObfConstantPoolAuthFlagTrapOnFailure ||
      descriptor->length != trusted_length || trusted_length > (uint64_t)SIZE_MAX) {
    ObfTrap();
  }

  derived_binding = ObfDeriveConstantPoolBindingId(descriptor->module_id, descriptor->pool_id);
  if (descriptor->binding_id != trusted_binding || descriptor->binding_id != derived_binding) {
    ObfTrap();
  }

  context->destination = descriptor->destination->target;
  context->ciphertext = descriptor->ciphertext->target;
  context->build_key = descriptor->build_key->target;
  context->length = (size_t)trusted_length;
  ObfDeriveFunctionKey(function_key, context->build_key, descriptor->module_id, 0u);
  ObfDeriveSiteKey(pool_key,
                   function_key,
                   kObfDomainConstant,
                   (uint32_t)sizeof(kObfDomainConstant),
                   descriptor->pool_id);
  ObfDeriveLabeledKey(
      context->enc_key, pool_key, kObfDomainEnc, (uint32_t)sizeof(kObfDomainEnc));
  ObfDeriveLabeledKey(
      context->mac_key, pool_key, kObfDomainMac, (uint32_t)sizeof(kObfDomainMac));

  expected_build_key_cookie = ObfDeriveBuildKeyCookie(
      context->build_key, kObfAuthDescriptorKindConstantPool, descriptor->binding_id, 32);
  destination_cookie = ObfDeriveReferenceCookie(context->mac_key,
                                                kObfAuthDescriptorKindConstantPool,
                                                descriptor->binding_id,
                                                kObfAuthReferenceRoleDestination,
                                                descriptor->destination_capacity);
  ciphertext_cookie = ObfDeriveReferenceCookie(context->mac_key,
                                                kObfAuthDescriptorKindConstantPool,
                                                descriptor->binding_id,
                                                kObfAuthReferenceRoleCiphertext,
                                                descriptor->ciphertext_capacity);
  state_cookie = ObfDeriveReferenceCookie(context->mac_key,
                                          kObfAuthDescriptorKindConstantPool,
                                          descriptor->binding_id,
                                          kObfAuthReferenceRoleState,
                                          0);
  if (descriptor->destination_cookie != destination_cookie ||
      descriptor->destination->cookie != destination_cookie ||
      descriptor->ciphertext_cookie != ciphertext_cookie ||
      descriptor->ciphertext->cookie != ciphertext_cookie ||
      descriptor->build_key_cookie != expected_build_key_cookie ||
      descriptor->build_key->cookie != expected_build_key_cookie ||
      descriptor->state_cookie != state_cookie || descriptor->state->cookie != state_cookie) {
    ObfTrap();
  }
  context->statuses.cold = ObfDeriveCacheColdStatus(context->mac_key,
                                                    kObfAuthDescriptorKindConstantPool,
                                                    descriptor->binding_id,
                                                    descriptor->destination_capacity,
                                                    descriptor->ciphertext_capacity,
                                                    descriptor->build_key_capacity);
}

static uint64_t ObfComputeDecodedCompletion(const uint8_t *mac_key,
                                            uint32_t descriptor_kind,
                                            const void *descriptor,
                                            const void *topology,
                                            const void *destination_ref,
                                            const void *ciphertext_ref,
                                            const void *build_key_ref,
                                            const void *state_ref,
                                            const uint8_t *destination,
                                            size_t length,
                                            uint32_t version,
                                            uint32_t flags,
                                            uint64_t descriptor_length,
                                            uint64_t module_id,
                                            uint64_t secondary_id,
                                            uint64_t site_id,
                                            uint64_t binding_id,
                                            uint64_t destination_cookie,
                                            uint64_t ciphertext_cookie,
                                            uint64_t build_key_cookie,
                                            uint64_t state_cookie,
                                            uint64_t destination_capacity,
                                            uint64_t ciphertext_capacity,
                                            uint64_t build_key_capacity,
                                            const uint8_t nonce[16]) {
  struct ObfBlake2sState state;
  uint8_t digest[32];
  ObfBlake2sInit(&state, 32, mac_key, 32);
  ObfBlake2sUpdateDomain(&state,
                         kObfDomainDecodedCompletionV3,
                         (uint32_t)sizeof(kObfDomainDecodedCompletionV3));
  ObfBlake2sUpdateU32(&state, descriptor_kind);
  ObfBlake2sUpdateU32(&state, version);
  ObfBlake2sUpdateU32(&state, flags);
  ObfBlake2sUpdateU64(&state, descriptor_length);
  ObfBlake2sUpdateU64(&state, module_id);
  ObfBlake2sUpdateU64(&state, secondary_id);
  ObfBlake2sUpdateU64(&state, site_id);
  ObfBlake2sUpdateU64(&state, binding_id);
  ObfBlake2sUpdateU64(&state, destination_cookie);
  ObfBlake2sUpdateU64(&state, ciphertext_cookie);
  ObfBlake2sUpdateU64(&state, build_key_cookie);
  ObfBlake2sUpdateU64(&state, state_cookie);
  ObfBlake2sUpdateU64(&state, destination_capacity);
  ObfBlake2sUpdateU64(&state, ciphertext_capacity);
  ObfBlake2sUpdateU64(&state, build_key_capacity);
  ObfBlake2sUpdate(&state, nonce, 16);
  ObfBlake2sUpdateU64(&state, (uint64_t)(uintptr_t)descriptor);
  ObfBlake2sUpdateU64(&state, (uint64_t)(uintptr_t)topology);
  ObfBlake2sUpdateU64(&state, (uint64_t)(uintptr_t)destination_ref);
  ObfBlake2sUpdateU64(&state, (uint64_t)(uintptr_t)ciphertext_ref);
  ObfBlake2sUpdateU64(&state, (uint64_t)(uintptr_t)build_key_ref);
  ObfBlake2sUpdateU64(&state, (uint64_t)(uintptr_t)state_ref);
  ObfBlake2sUpdate(&state, destination, length);
  ObfBlake2sFinal(&state, digest);
  return ObfNormalizeDerivedWord(ObfLoad64(digest), binding_id, (uint64_t)length);
}

static void ObfVerifyStringTag(const struct ObfStringValidationContext *context,
                               const struct ObfStringRuntimeDescriptorV3 *descriptor) {
  uint8_t tag[16];
  ObfComputeStringTag(tag, context->mac_key, descriptor, context->ciphertext, context->length);
  if (!ObfConstantTimeEqual(tag, descriptor->tag, sizeof(tag))) {
    ObfTrap();
  }
}

static void ObfVerifyConstantPoolTag(
    const struct ObfConstantPoolValidationContext *context,
    const struct ObfConstantPoolRuntimeDescriptorV3 *descriptor) {
  uint8_t tag[16];
  ObfComputeConstantPoolTag(
      tag, context->mac_key, descriptor, context->ciphertext, context->length);
  if (!ObfConstantTimeEqual(tag, descriptor->tag, sizeof(tag))) {
    ObfTrap();
  }
}

static uint64_t ObfStringCompletion(const struct ObfStringValidationContext *context,
                                    const struct ObfStringRuntimeDescriptorV3 *descriptor,
                                    const struct ObfAuthenticatedDecodeTopologyV3 *topology) {
  return ObfComputeDecodedCompletion(context->mac_key,
                                     kObfAuthDescriptorKindString,
                                     descriptor,
                                     topology,
                                     descriptor->destination,
                                     descriptor->ciphertext,
                                     descriptor->build_key,
                                     descriptor->state,
                                     context->destination,
                                     context->length,
                                     descriptor->version,
                                     descriptor->flags,
                                     descriptor->length,
                                     descriptor->module_id,
                                     descriptor->function_id,
                                     descriptor->site_id,
                                     descriptor->binding_id,
                                     descriptor->destination_cookie,
                                     descriptor->ciphertext_cookie,
                                     descriptor->build_key_cookie,
                                     descriptor->state_cookie,
                                     descriptor->destination_capacity,
                                     descriptor->ciphertext_capacity,
                                     descriptor->build_key_capacity,
                                     descriptor->nonce);
}

static uint64_t ObfConstantPoolCompletion(
    const struct ObfConstantPoolValidationContext *context,
    const struct ObfConstantPoolRuntimeDescriptorV3 *descriptor,
    const struct ObfAuthenticatedDecodeTopologyV3 *topology) {
  return ObfComputeDecodedCompletion(context->mac_key,
                                     kObfAuthDescriptorKindConstantPool,
                                     descriptor,
                                     topology,
                                     descriptor->destination,
                                     descriptor->ciphertext,
                                     descriptor->build_key,
                                     descriptor->state,
                                     context->destination,
                                     context->length,
                                     descriptor->version,
                                     descriptor->flags,
                                     descriptor->length,
                                     descriptor->module_id,
                                     descriptor->pool_id,
                                     0,
                                     descriptor->binding_id,
                                     descriptor->destination_cookie,
                                     descriptor->ciphertext_cookie,
                                     descriptor->build_key_cookie,
                                     descriptor->state_cookie,
                                     descriptor->destination_capacity,
                                     descriptor->ciphertext_capacity,
                                     descriptor->build_key_capacity,
                                     descriptor->nonce);
}

static uint8_t *ObfWaitForStringDecode(
    struct ObfStringValidationContext *context,
    const struct ObfStringRuntimeDescriptorV3 *descriptor,
    const struct ObfAuthenticatedDecodeTopologyV3 *topology) {
  uint32_t poll;
  for (poll = 0; poll < kObfDecodePollLimit; ++poll) {
    const uint64_t status = ObfAtomicLoadU64Acquire(&descriptor->state->status);
    const uint64_t completion = ObfAtomicLoadU64Acquire(&descriptor->state->completion);
    ObfVerifyStringTag(context, descriptor);
    if (status == context->statuses.decoded) {
      const uint64_t expected_completion = ObfStringCompletion(context, descriptor, topology);
      if (completion != expected_completion) {
        ObfTrap();
      }
      return context->destination;
    }
    if ((status == context->statuses.cold && completion == context->statuses.decoding) ||
        (status == context->statuses.decoding && completion == context->statuses.decoding)) {
      continue;
    }
    ObfTrap();
  }
  ObfTrap();
  return NULL;
}

static uint8_t *ObfWaitForConstantPoolDecode(
    struct ObfConstantPoolValidationContext *context,
    const struct ObfConstantPoolRuntimeDescriptorV3 *descriptor,
    const struct ObfAuthenticatedDecodeTopologyV3 *topology) {
  uint32_t poll;
  for (poll = 0; poll < kObfDecodePollLimit; ++poll) {
    const uint64_t status = ObfAtomicLoadU64Acquire(&descriptor->state->status);
    const uint64_t completion = ObfAtomicLoadU64Acquire(&descriptor->state->completion);
    ObfVerifyConstantPoolTag(context, descriptor);
    if (status == context->statuses.decoded) {
      const uint64_t expected_completion = ObfConstantPoolCompletion(context, descriptor, topology);
      if (completion != expected_completion) {
        ObfTrap();
      }
      return context->destination;
    }
    if ((status == context->statuses.cold && completion == context->statuses.decoding) ||
        (status == context->statuses.decoding && completion == context->statuses.decoding)) {
      continue;
    }
    ObfTrap();
  }
  ObfTrap();
  return NULL;
}

__attribute__((visibility("hidden")))
uint8_t *OBF_RT_STRING_AUTH_DECODE_V3(
    const struct ObfStringRuntimeDescriptorV3 *descriptor,
    uint64_t trusted_length,
    uint64_t trusted_binding,
    const struct ObfAuthenticatedDecodeTopologyV3 *trusted_topology) {
  struct ObfStringValidationContext context;
  ObfValidateStringDescriptor(
      &context, descriptor, trusted_length, trusted_binding, trusted_topology);
  ObfVerifyStringTag(&context, descriptor);
  ObfDeriveRelocationStatuses(&context.statuses,
                              context.mac_key,
                              kObfAuthDescriptorKindString,
                              descriptor->binding_id,
                              descriptor,
                              trusted_topology,
                              descriptor->state);

  for (uint32_t poll = 0; poll < kObfDecodePollLimit; ++poll) {
    ObfVerifyStringTag(&context, descriptor);
    const uint64_t status = ObfAtomicLoadU64Acquire(&descriptor->state->status);
    const uint64_t completion = ObfAtomicLoadU64Acquire(&descriptor->state->completion);
    if (status == context.statuses.decoded) {
      const uint64_t expected_completion = ObfStringCompletion(&context, descriptor, trusted_topology);
      ObfVerifyStringTag(&context, descriptor);
      if (completion != expected_completion) {
        ObfTrap();
      }
      return context.destination;
    }
    if (status == context.statuses.cold && completion == context.statuses.cold) {
      uint64_t expected = context.statuses.cold;
      if (ObfAtomicCompareExchangeU64AcqRelRelaxed(
              &descriptor->state->completion, &expected, context.statuses.decoding)) {
        ObfAtomicStoreU64Release(&descriptor->state->status, context.statuses.decoding);
        ObfVerifyStringTag(&context, descriptor);
        ObfDecodePayload(
            context.destination, context.ciphertext, context.enc_key, descriptor->nonce, context.length);
        const uint64_t decoded_completion =
            ObfStringCompletion(&context, descriptor, trusted_topology);
        ObfAtomicStoreU64Release(&descriptor->state->completion, decoded_completion);
        ObfAtomicStoreU64Release(&descriptor->state->status, context.statuses.decoded);
        return context.destination;
      }
      continue;
    }
    if ((status == context.statuses.cold && completion == context.statuses.decoding) ||
        (status == context.statuses.decoding && completion == context.statuses.decoding)) {
      return ObfWaitForStringDecode(&context, descriptor, trusted_topology);
    }
    ObfTrap();
  }
  ObfTrap();
  return NULL;
}

__attribute__((visibility("hidden")))
uint8_t *OBF_RT_CONSTANT_POOL_DECODE_V3(
    const struct ObfConstantPoolRuntimeDescriptorV3 *descriptor,
    uint64_t trusted_length,
    uint64_t trusted_binding,
    const struct ObfAuthenticatedDecodeTopologyV3 *trusted_topology) {
  struct ObfConstantPoolValidationContext context;
  ObfValidateConstantPoolDescriptor(
      &context, descriptor, trusted_length, trusted_binding, trusted_topology);
  ObfVerifyConstantPoolTag(&context, descriptor);
  ObfDeriveRelocationStatuses(&context.statuses,
                              context.mac_key,
                              kObfAuthDescriptorKindConstantPool,
                              descriptor->binding_id,
                              descriptor,
                              trusted_topology,
                              descriptor->state);

  for (uint32_t poll = 0; poll < kObfDecodePollLimit; ++poll) {
    ObfVerifyConstantPoolTag(&context, descriptor);
    const uint64_t status = ObfAtomicLoadU64Acquire(&descriptor->state->status);
    const uint64_t completion = ObfAtomicLoadU64Acquire(&descriptor->state->completion);
    if (status == context.statuses.decoded) {
      const uint64_t expected_completion =
          ObfConstantPoolCompletion(&context, descriptor, trusted_topology);
      ObfVerifyConstantPoolTag(&context, descriptor);
      if (completion != expected_completion) {
        ObfTrap();
      }
      return context.destination;
    }
    if (status == context.statuses.cold && completion == context.statuses.cold) {
      uint64_t expected = context.statuses.cold;
      if (ObfAtomicCompareExchangeU64AcqRelRelaxed(
              &descriptor->state->completion, &expected, context.statuses.decoding)) {
        ObfAtomicStoreU64Release(&descriptor->state->status, context.statuses.decoding);
        ObfVerifyConstantPoolTag(&context, descriptor);
        ObfDecodePayload(
            context.destination, context.ciphertext, context.enc_key, descriptor->nonce, context.length);
        const uint64_t decoded_completion =
            ObfConstantPoolCompletion(&context, descriptor, trusted_topology);
        ObfAtomicStoreU64Release(&descriptor->state->completion, decoded_completion);
        ObfAtomicStoreU64Release(&descriptor->state->status, context.statuses.decoded);
        return context.destination;
      }
      continue;
    }
    if ((status == context.statuses.cold && completion == context.statuses.decoding) ||
        (status == context.statuses.decoding && completion == context.statuses.decoding)) {
      return ObfWaitForConstantPoolDecode(&context, descriptor, trusted_topology);
    }
  }
  ObfTrap();
  return NULL;
}
