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

struct ObfAuthenticatedBufferReferenceV2 {
  uint64_t cookie;
  uint8_t *target;
};

struct ObfAuthenticatedStateReferenceV2 {
  uint64_t cookie;
  uint64_t status;
};

struct ObfStringRuntimeDescriptorV2 {
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
  uint8_t nonce[16];
  uint8_t tag[16];
  struct ObfAuthenticatedBufferReferenceV2 *destination;
  const struct ObfAuthenticatedBufferReferenceV2 *ciphertext;
  const struct ObfAuthenticatedBufferReferenceV2 *build_key;
  struct ObfAuthenticatedStateReferenceV2 *state;
};

struct ObfConstantPoolRuntimeDescriptorV2 {
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
  uint8_t nonce[16];
  uint8_t tag[16];
  struct ObfAuthenticatedBufferReferenceV2 *destination;
  const struct ObfAuthenticatedBufferReferenceV2 *ciphertext;
  const struct ObfAuthenticatedBufferReferenceV2 *build_key;
  struct ObfAuthenticatedStateReferenceV2 *state;
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
  kObfStringDescriptorVersionV2 = 2,
  kObfStringAuthFlagTrapOnFailure = 1u,
  kObfConstantPoolDescriptorVersionV2 = 2,
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
};

#define OBF_MAX_SIZE(lhs, rhs) ((lhs) < (rhs) ? (rhs) : (lhs))
#define OBF_ROUND_UP_SIZE(value, alignment) \
  (((value) + (alignment) - 1) / (alignment) * (alignment))

_Static_assert(offsetof(struct ObfAuthenticatedBufferReferenceV2, cookie) == 0,
               "buffer reference cookie offset must match host ABI");
_Static_assert(offsetof(struct ObfAuthenticatedBufferReferenceV2, target) ==
                   OBF_ROUND_UP_SIZE(sizeof(uint64_t), _Alignof(uint8_t *)),
               "buffer reference target offset must match host ABI");
_Static_assert(sizeof(struct ObfAuthenticatedBufferReferenceV2) ==
                   OBF_ROUND_UP_SIZE(offsetof(struct ObfAuthenticatedBufferReferenceV2, target) +
                                         sizeof(((struct ObfAuthenticatedBufferReferenceV2 *)0)->target),
                                     _Alignof(struct ObfAuthenticatedBufferReferenceV2)),
               "buffer reference size must match host ABI");
_Static_assert(_Alignof(struct ObfAuthenticatedBufferReferenceV2) ==
                   OBF_MAX_SIZE(_Alignof(uint64_t), _Alignof(uint8_t *)),
               "buffer reference alignment must match host ABI");
_Static_assert(offsetof(struct ObfAuthenticatedStateReferenceV2, cookie) == 0,
               "state reference cookie offset must match host ABI");
_Static_assert(offsetof(struct ObfAuthenticatedStateReferenceV2, status) ==
                   OBF_ROUND_UP_SIZE(sizeof(uint64_t), _Alignof(uint64_t)),
               "state reference status offset must match host ABI");
_Static_assert(sizeof(struct ObfAuthenticatedStateReferenceV2) ==
                   OBF_ROUND_UP_SIZE(offsetof(struct ObfAuthenticatedStateReferenceV2, status) +
                                         sizeof(((struct ObfAuthenticatedStateReferenceV2 *)0)->status),
                                     _Alignof(struct ObfAuthenticatedStateReferenceV2)),
               "state reference size must match host ABI");
_Static_assert(_Alignof(struct ObfAuthenticatedStateReferenceV2) == _Alignof(uint64_t),
               "state reference alignment must match host ABI");
_Static_assert(offsetof(struct ObfStringRuntimeDescriptorV2, version) == 0,
               "string descriptor version offset must match host ABI");
_Static_assert(offsetof(struct ObfStringRuntimeDescriptorV2, flags) == sizeof(uint32_t),
               "string descriptor flags offset must match host ABI");
_Static_assert(offsetof(struct ObfStringRuntimeDescriptorV2, length) == sizeof(uint64_t),
               "string descriptor length offset must match host ABI");
_Static_assert(offsetof(struct ObfStringRuntimeDescriptorV2, module_id) ==
                   offsetof(struct ObfStringRuntimeDescriptorV2, length) +
                       sizeof(((struct ObfStringRuntimeDescriptorV2 *)0)->length),
               "string descriptor module_id offset must match host ABI");
_Static_assert(offsetof(struct ObfStringRuntimeDescriptorV2, function_id) ==
                   offsetof(struct ObfStringRuntimeDescriptorV2, module_id) +
                       sizeof(((struct ObfStringRuntimeDescriptorV2 *)0)->module_id),
               "string descriptor function_id offset must match host ABI");
_Static_assert(offsetof(struct ObfStringRuntimeDescriptorV2, site_id) ==
                   offsetof(struct ObfStringRuntimeDescriptorV2, function_id) +
                       sizeof(((struct ObfStringRuntimeDescriptorV2 *)0)->function_id),
               "string descriptor site_id offset must match host ABI");
_Static_assert(offsetof(struct ObfStringRuntimeDescriptorV2, binding_id) ==
                   offsetof(struct ObfStringRuntimeDescriptorV2, site_id) +
                       sizeof(((struct ObfStringRuntimeDescriptorV2 *)0)->site_id),
               "string descriptor binding_id offset must match host ABI");
_Static_assert(offsetof(struct ObfStringRuntimeDescriptorV2, destination_cookie) ==
                   offsetof(struct ObfStringRuntimeDescriptorV2, binding_id) +
                       sizeof(((struct ObfStringRuntimeDescriptorV2 *)0)->binding_id),
               "string descriptor destination_cookie offset must match host ABI");
_Static_assert(offsetof(struct ObfStringRuntimeDescriptorV2, ciphertext_cookie) ==
                   offsetof(struct ObfStringRuntimeDescriptorV2, destination_cookie) +
                       sizeof(((struct ObfStringRuntimeDescriptorV2 *)0)->destination_cookie),
               "string descriptor ciphertext_cookie offset must match host ABI");
_Static_assert(offsetof(struct ObfStringRuntimeDescriptorV2, build_key_cookie) ==
                   offsetof(struct ObfStringRuntimeDescriptorV2, ciphertext_cookie) +
                       sizeof(((struct ObfStringRuntimeDescriptorV2 *)0)->ciphertext_cookie),
               "string descriptor build_key_cookie offset must match host ABI");
_Static_assert(offsetof(struct ObfStringRuntimeDescriptorV2, state_cookie) ==
                   offsetof(struct ObfStringRuntimeDescriptorV2, build_key_cookie) +
                       sizeof(((struct ObfStringRuntimeDescriptorV2 *)0)->build_key_cookie),
               "string descriptor state_cookie offset must match host ABI");
_Static_assert(offsetof(struct ObfStringRuntimeDescriptorV2, nonce) ==
                   offsetof(struct ObfStringRuntimeDescriptorV2, state_cookie) +
                       sizeof(((struct ObfStringRuntimeDescriptorV2 *)0)->state_cookie),
               "string descriptor nonce offset must match host ABI");
_Static_assert(offsetof(struct ObfStringRuntimeDescriptorV2, tag) ==
                   offsetof(struct ObfStringRuntimeDescriptorV2, nonce) +
                       sizeof(((struct ObfStringRuntimeDescriptorV2 *)0)->nonce),
               "string descriptor tag offset must match host ABI");
_Static_assert(offsetof(struct ObfStringRuntimeDescriptorV2, destination) ==
                   offsetof(struct ObfStringRuntimeDescriptorV2, tag) +
                       sizeof(((struct ObfStringRuntimeDescriptorV2 *)0)->tag),
               "string descriptor destination reference offset must match host ABI");
_Static_assert(offsetof(struct ObfStringRuntimeDescriptorV2, destination) %
                       _Alignof(struct ObfAuthenticatedBufferReferenceV2 *) ==
                   0,
               "string descriptor destination reference alignment must match host ABI");
_Static_assert(offsetof(struct ObfStringRuntimeDescriptorV2, ciphertext) ==
                   offsetof(struct ObfStringRuntimeDescriptorV2, destination) +
                       sizeof(((struct ObfStringRuntimeDescriptorV2 *)0)->destination),
               "string descriptor ciphertext reference offset must match host ABI");
_Static_assert(offsetof(struct ObfStringRuntimeDescriptorV2, build_key) ==
                   offsetof(struct ObfStringRuntimeDescriptorV2, ciphertext) +
                       sizeof(((struct ObfStringRuntimeDescriptorV2 *)0)->ciphertext),
               "string descriptor build_key reference offset must match host ABI");
_Static_assert(offsetof(struct ObfStringRuntimeDescriptorV2, state) ==
                   offsetof(struct ObfStringRuntimeDescriptorV2, build_key) +
                       sizeof(((struct ObfStringRuntimeDescriptorV2 *)0)->build_key),
               "string descriptor state reference offset must match host ABI");
_Static_assert(offsetof(struct ObfConstantPoolRuntimeDescriptorV2, version) == 0,
               "constant pool descriptor version offset must match host ABI");
_Static_assert(offsetof(struct ObfConstantPoolRuntimeDescriptorV2, flags) == sizeof(uint32_t),
               "constant pool descriptor flags offset must match host ABI");
_Static_assert(offsetof(struct ObfConstantPoolRuntimeDescriptorV2, length) == sizeof(uint64_t),
               "constant pool descriptor length offset must match host ABI");
_Static_assert(offsetof(struct ObfConstantPoolRuntimeDescriptorV2, module_id) ==
                   offsetof(struct ObfConstantPoolRuntimeDescriptorV2, length) +
                       sizeof(((struct ObfConstantPoolRuntimeDescriptorV2 *)0)->length),
               "constant pool descriptor module_id offset must match host ABI");
_Static_assert(offsetof(struct ObfConstantPoolRuntimeDescriptorV2, pool_id) ==
                   offsetof(struct ObfConstantPoolRuntimeDescriptorV2, module_id) +
                       sizeof(((struct ObfConstantPoolRuntimeDescriptorV2 *)0)->module_id),
               "constant pool descriptor pool_id offset must match host ABI");
_Static_assert(offsetof(struct ObfConstantPoolRuntimeDescriptorV2, binding_id) ==
                   offsetof(struct ObfConstantPoolRuntimeDescriptorV2, pool_id) +
                       sizeof(((struct ObfConstantPoolRuntimeDescriptorV2 *)0)->pool_id),
               "constant pool descriptor binding_id offset must match host ABI");
_Static_assert(offsetof(struct ObfConstantPoolRuntimeDescriptorV2, destination_cookie) ==
                   offsetof(struct ObfConstantPoolRuntimeDescriptorV2, binding_id) +
                       sizeof(((struct ObfConstantPoolRuntimeDescriptorV2 *)0)->binding_id),
               "constant pool descriptor destination_cookie offset must match host ABI");
_Static_assert(offsetof(struct ObfConstantPoolRuntimeDescriptorV2, ciphertext_cookie) ==
                   offsetof(struct ObfConstantPoolRuntimeDescriptorV2, destination_cookie) +
                       sizeof(((struct ObfConstantPoolRuntimeDescriptorV2 *)0)->destination_cookie),
               "constant pool descriptor ciphertext_cookie offset must match host ABI");
_Static_assert(offsetof(struct ObfConstantPoolRuntimeDescriptorV2, build_key_cookie) ==
                   offsetof(struct ObfConstantPoolRuntimeDescriptorV2, ciphertext_cookie) +
                       sizeof(((struct ObfConstantPoolRuntimeDescriptorV2 *)0)->ciphertext_cookie),
               "constant pool descriptor build_key_cookie offset must match host ABI");
_Static_assert(offsetof(struct ObfConstantPoolRuntimeDescriptorV2, state_cookie) ==
                   offsetof(struct ObfConstantPoolRuntimeDescriptorV2, build_key_cookie) +
                       sizeof(((struct ObfConstantPoolRuntimeDescriptorV2 *)0)->build_key_cookie),
               "constant pool descriptor state_cookie offset must match host ABI");
_Static_assert(offsetof(struct ObfConstantPoolRuntimeDescriptorV2, nonce) ==
                   offsetof(struct ObfConstantPoolRuntimeDescriptorV2, state_cookie) +
                       sizeof(((struct ObfConstantPoolRuntimeDescriptorV2 *)0)->state_cookie),
               "constant pool descriptor nonce offset must match host ABI");
_Static_assert(offsetof(struct ObfConstantPoolRuntimeDescriptorV2, tag) ==
                   offsetof(struct ObfConstantPoolRuntimeDescriptorV2, nonce) +
                       sizeof(((struct ObfConstantPoolRuntimeDescriptorV2 *)0)->nonce),
               "constant pool descriptor tag offset must match host ABI");
_Static_assert(offsetof(struct ObfConstantPoolRuntimeDescriptorV2, destination) ==
                   offsetof(struct ObfConstantPoolRuntimeDescriptorV2, tag) +
                       sizeof(((struct ObfConstantPoolRuntimeDescriptorV2 *)0)->tag),
               "constant pool descriptor destination reference offset must match host ABI");
_Static_assert(offsetof(struct ObfConstantPoolRuntimeDescriptorV2, destination) %
                       _Alignof(struct ObfAuthenticatedBufferReferenceV2 *) ==
                   0,
               "constant pool descriptor destination reference alignment must match host ABI");
_Static_assert(offsetof(struct ObfConstantPoolRuntimeDescriptorV2, ciphertext) ==
                   offsetof(struct ObfConstantPoolRuntimeDescriptorV2, destination) +
                       sizeof(((struct ObfConstantPoolRuntimeDescriptorV2 *)0)->destination),
               "constant pool descriptor ciphertext reference offset must match host ABI");
_Static_assert(offsetof(struct ObfConstantPoolRuntimeDescriptorV2, build_key) ==
                   offsetof(struct ObfConstantPoolRuntimeDescriptorV2, ciphertext) +
                       sizeof(((struct ObfConstantPoolRuntimeDescriptorV2 *)0)->ciphertext),
               "constant pool descriptor build_key reference offset must match host ABI");
_Static_assert(offsetof(struct ObfConstantPoolRuntimeDescriptorV2, state) ==
                   offsetof(struct ObfConstantPoolRuntimeDescriptorV2, build_key) +
                       sizeof(((struct ObfConstantPoolRuntimeDescriptorV2 *)0)->build_key),
               "constant pool descriptor state reference offset must match host ABI");

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
static const uint8_t kObfDomainStringBindingV2[17] = {
    's', 't', 'r', 'i', 'n', 'g', '_', 'b', 'i', 'n', 'd', 'i', 'n', 'g', '_', 'v', '2'};
static const uint8_t kObfDomainConstantBindingV2[19] = {
    'c', 'o', 'n', 's', 't', 'a', 'n', 't', '_', 'b', 'i', 'n', 'd', 'i', 'n', 'g', '_', 'v', '2'};
static const uint8_t kObfDomainReferenceCookieV2[19] = {
    'r', 'e', 'f', 'e', 'r', 'e', 'n', 'c', 'e', '_', 'c', 'o', 'o', 'k', 'i', 'e', '_', 'v', '2'};
static const uint8_t kObfDomainBuildKeyCookieV2[19] = {
    'b', 'u', 'i', 'l', 'd', '_', 'k', 'e', 'y', '_', 'c', 'o', 'o', 'k', 'i', 'e', '_', 'v', '2'};
static const uint8_t kObfDomainCacheStatusV2[15] = {
    'c', 'a', 'c', 'h', 'e', '_', 's', 't', 'a', 't', 'u', 's', '_', 'v', '2'};

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
                         kObfDomainStringBindingV2,
                         (uint32_t)sizeof(kObfDomainStringBindingV2));
  ObfBlake2sUpdateU64(&state, module_id);
  ObfBlake2sUpdateU64(&state, function_id);
  ObfBlake2sUpdateU64(&state, site_id);
  return ObfFinalizeDerivedWord(&state, module_id ^ function_id, site_id);
}

static uint64_t ObfDeriveConstantPoolBindingId(uint64_t module_id, uint64_t pool_id) {
  struct ObfBlake2sState state;
  ObfBlake2sInit(&state, 32, NULL, 0);
  ObfBlake2sUpdateDomain(&state,
                         kObfDomainConstantBindingV2,
                         (uint32_t)sizeof(kObfDomainConstantBindingV2));
  ObfBlake2sUpdateU64(&state, module_id);
  ObfBlake2sUpdateU64(&state, pool_id);
  return ObfFinalizeDerivedWord(&state, module_id, pool_id);
}

static uint64_t ObfDeriveReferenceCookie(const uint8_t *mac_key,
                                         uint32_t descriptor_kind,
                                         uint64_t binding_id,
                                         uint32_t role) {
  struct ObfBlake2sState state;
  ObfBlake2sInit(&state, 32, mac_key, 32);
  ObfBlake2sUpdateDomain(&state,
                         kObfDomainReferenceCookieV2,
                         (uint32_t)sizeof(kObfDomainReferenceCookieV2));
  ObfBlake2sUpdateU32(&state, descriptor_kind);
  ObfBlake2sUpdateU64(&state, binding_id);
  ObfBlake2sUpdateU32(&state, role);
  return ObfFinalizeDerivedWord(&state, binding_id, role);
}

static uint64_t ObfDeriveBuildKeyCookie(const uint8_t *build_key,
                                        uint32_t descriptor_kind,
                                        uint64_t binding_id) {
  struct ObfBlake2sState state;
  ObfBlake2sInit(&state, 32, build_key, kObfBuildKeyBytes);
  ObfBlake2sUpdateDomain(&state,
                         kObfDomainBuildKeyCookieV2,
                         (uint32_t)sizeof(kObfDomainBuildKeyCookieV2));
  ObfBlake2sUpdateU32(&state, descriptor_kind);
  ObfBlake2sUpdateU64(&state, binding_id);
  ObfBlake2sUpdateU32(&state, kObfAuthReferenceRoleBuildKey);
  return ObfFinalizeDerivedWord(&state, binding_id, kObfAuthReferenceRoleBuildKey);
}

static struct ObfCacheStatusSet ObfDeriveCacheStatuses(const uint8_t *mac_key,
                                                       uint32_t descriptor_kind,
                                                       uint64_t binding_id) {
  struct ObfCacheStatusSet statuses;
  struct ObfBlake2sState state;

  ObfBlake2sInit(&state, 32, mac_key, 32);
  ObfBlake2sUpdateDomain(&state,
                         kObfDomainCacheStatusV2,
                         (uint32_t)sizeof(kObfDomainCacheStatusV2));
  ObfBlake2sUpdateU32(&state, descriptor_kind);
  ObfBlake2sUpdateU64(&state, binding_id);
  ObfBlake2sUpdateU32(&state, 0u);

  statuses.cold = ObfFinalizeDerivedWord(&state, binding_id, kObfCacheStatusCold);
  statuses.decoding = ObfNormalizeDerivedWord(
      statuses.cold ^ 0x6a09e667f3bcc909ULL, binding_id, kObfCacheStatusDecoding);
  statuses.decoded = ObfNormalizeDerivedWord(
      statuses.cold ^ 0xbb67ae8584caa73bULL, binding_id, kObfCacheStatusDecoded);

  if (statuses.decoding == statuses.cold) {
    statuses.decoding ^= 0x3c6ef372fe94f82bULL;
    statuses.decoding =
        ObfNormalizeDerivedWord(statuses.decoding, binding_id, kObfCacheStatusDecoding);
  }

  if (statuses.decoded == statuses.cold || statuses.decoded == statuses.decoding) {
    statuses.decoded ^= 0x3c6ef372fe94f82bULL;
    statuses.decoded =
        ObfNormalizeDerivedWord(statuses.decoded, binding_id, kObfCacheStatusDecoded);
  }

  return statuses;
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
                                const struct ObfStringRuntimeDescriptorV2 *descriptor,
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
  ObfBlake2sUpdateU64(&state, descriptor->binding_id);
  ObfBlake2sUpdateU64(&state, descriptor->destination_cookie);
  ObfBlake2sUpdateU64(&state, descriptor->ciphertext_cookie);
  ObfBlake2sUpdateU64(&state, descriptor->build_key_cookie);
  ObfBlake2sUpdateU64(&state, descriptor->state_cookie);
  ObfBlake2sUpdate(&state, descriptor->nonce, sizeof(descriptor->nonce));
  ObfBlake2sUpdate(&state, descriptor->ciphertext->target, ciphertext_size);
  ObfBlake2sFinal(&state, digest);
  memcpy(output, digest, 16);
}

static void ObfComputeConstantPoolTag(uint8_t output[16],
                                      const uint8_t *mac_key,
                                      const struct ObfConstantPoolRuntimeDescriptorV2 *descriptor,
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
  ObfBlake2sUpdateU64(&state, descriptor->binding_id);
  ObfBlake2sUpdateU64(&state, descriptor->destination_cookie);
  ObfBlake2sUpdateU64(&state, descriptor->ciphertext_cookie);
  ObfBlake2sUpdateU64(&state, descriptor->build_key_cookie);
  ObfBlake2sUpdateU64(&state, descriptor->state_cookie);
  ObfBlake2sUpdate(&state, descriptor->nonce, sizeof(descriptor->nonce));
  ObfBlake2sUpdate(&state, descriptor->ciphertext->target, ciphertext_size);
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

static uint64_t ObfValidateStringDescriptor(struct ObfStringValidationContext *context,
                                            const struct ObfStringRuntimeDescriptorV2 *descriptor,
                                            uint64_t trusted_length,
                                            uint64_t trusted_binding) {
  uint8_t function_key[32];
  uint8_t site_key[32];
  uint64_t derived_binding;
  uint64_t expected_build_key_cookie;
  uint64_t destination_cookie;
  uint64_t ciphertext_cookie;
  uint64_t state_cookie;

  if (descriptor == NULL || descriptor->destination == NULL || descriptor->ciphertext == NULL ||
      descriptor->build_key == NULL || descriptor->state == NULL) {
    ObfTrap();
  }

  if (descriptor->destination->target == NULL || descriptor->ciphertext->target == NULL ||
      descriptor->build_key->target == NULL) {
    ObfTrap();
  }

  if (descriptor->version != kObfStringDescriptorVersionV2) {
    ObfTrap();
  }

  if (descriptor->flags != kObfStringAuthFlagTrapOnFailure) {
    ObfTrap();
  }

  if (descriptor->length != trusted_length || trusted_length > (uint64_t)SIZE_MAX) {
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

  ObfDeriveFunctionKey(function_key,
                       context->build_key,
                       descriptor->module_id,
                       descriptor->function_id);
  ObfDeriveSiteKey(site_key,
                   function_key,
                   kObfDomainString,
                   (uint32_t)sizeof(kObfDomainString),
                   descriptor->site_id);
  ObfDeriveLabeledKey(context->enc_key,
                      site_key,
                      kObfDomainEnc,
                      (uint32_t)sizeof(kObfDomainEnc));
  ObfDeriveLabeledKey(context->mac_key,
                      site_key,
                      kObfDomainMac,
                      (uint32_t)sizeof(kObfDomainMac));

  expected_build_key_cookie = ObfDeriveBuildKeyCookie(
      context->build_key, kObfAuthDescriptorKindString, descriptor->binding_id);

  destination_cookie = ObfDeriveReferenceCookie(
      context->mac_key,
      kObfAuthDescriptorKindString,
      descriptor->binding_id,
      kObfAuthReferenceRoleDestination);
  ciphertext_cookie = ObfDeriveReferenceCookie(
      context->mac_key,
      kObfAuthDescriptorKindString,
      descriptor->binding_id,
      kObfAuthReferenceRoleCiphertext);
  state_cookie = ObfDeriveReferenceCookie(
      context->mac_key,
      kObfAuthDescriptorKindString,
      descriptor->binding_id,
      kObfAuthReferenceRoleState);

  if (descriptor->destination_cookie != destination_cookie ||
      descriptor->destination->cookie != destination_cookie ||
      descriptor->ciphertext_cookie != ciphertext_cookie ||
      descriptor->ciphertext->cookie != ciphertext_cookie ||
      descriptor->build_key_cookie != expected_build_key_cookie ||
      descriptor->build_key->cookie != expected_build_key_cookie ||
      descriptor->state_cookie != state_cookie ||
      descriptor->state->cookie != state_cookie) {
    ObfTrap();
  }

  context->statuses =
      ObfDeriveCacheStatuses(context->mac_key, kObfAuthDescriptorKindString, descriptor->binding_id);
  return ObfAtomicLoadU64Acquire(&descriptor->state->status);
}

static uint64_t ObfValidateConstantPoolDescriptor(
    struct ObfConstantPoolValidationContext *context,
    const struct ObfConstantPoolRuntimeDescriptorV2 *descriptor,
    uint64_t trusted_length,
    uint64_t trusted_binding) {
  uint8_t function_key[32];
  uint8_t pool_key[32];
  uint64_t derived_binding;
  uint64_t expected_build_key_cookie;
  uint64_t destination_cookie;
  uint64_t ciphertext_cookie;
  uint64_t state_cookie;

  if (descriptor == NULL || descriptor->destination == NULL || descriptor->ciphertext == NULL ||
      descriptor->build_key == NULL || descriptor->state == NULL) {
    ObfTrap();
  }

  if (descriptor->destination->target == NULL || descriptor->ciphertext->target == NULL ||
      descriptor->build_key->target == NULL) {
    ObfTrap();
  }

  if (descriptor->version != kObfConstantPoolDescriptorVersionV2) {
    ObfTrap();
  }

  if (descriptor->flags != kObfConstantPoolAuthFlagTrapOnFailure) {
    ObfTrap();
  }

  if (descriptor->length != trusted_length || trusted_length > (uint64_t)SIZE_MAX) {
    ObfTrap();
  }

  derived_binding =
      ObfDeriveConstantPoolBindingId(descriptor->module_id, descriptor->pool_id);

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
  ObfDeriveLabeledKey(context->enc_key,
                      pool_key,
                      kObfDomainEnc,
                      (uint32_t)sizeof(kObfDomainEnc));
  ObfDeriveLabeledKey(context->mac_key,
                      pool_key,
                      kObfDomainMac,
                      (uint32_t)sizeof(kObfDomainMac));

  expected_build_key_cookie = ObfDeriveBuildKeyCookie(
      context->build_key, kObfAuthDescriptorKindConstantPool, descriptor->binding_id);

  destination_cookie = ObfDeriveReferenceCookie(
      context->mac_key,
      kObfAuthDescriptorKindConstantPool,
      descriptor->binding_id,
      kObfAuthReferenceRoleDestination);
  ciphertext_cookie = ObfDeriveReferenceCookie(
      context->mac_key,
      kObfAuthDescriptorKindConstantPool,
      descriptor->binding_id,
      kObfAuthReferenceRoleCiphertext);
  state_cookie = ObfDeriveReferenceCookie(
      context->mac_key,
      kObfAuthDescriptorKindConstantPool,
      descriptor->binding_id,
      kObfAuthReferenceRoleState);

  if (descriptor->destination_cookie != destination_cookie ||
      descriptor->destination->cookie != destination_cookie ||
      descriptor->ciphertext_cookie != ciphertext_cookie ||
      descriptor->ciphertext->cookie != ciphertext_cookie ||
      descriptor->build_key_cookie != expected_build_key_cookie ||
      descriptor->build_key->cookie != expected_build_key_cookie ||
      descriptor->state_cookie != state_cookie ||
      descriptor->state->cookie != state_cookie) {
    ObfTrap();
  }

  context->statuses = ObfDeriveCacheStatuses(
      context->mac_key, kObfAuthDescriptorKindConstantPool, descriptor->binding_id);
  return ObfAtomicLoadU64Acquire(&descriptor->state->status);
}

static uint8_t *ObfHandleStringObservedStatus(struct ObfStringValidationContext *context,
                                              const struct ObfStringRuntimeDescriptorV2 *descriptor,
                                              uint64_t trusted_length,
                                              uint64_t trusted_binding,
                                              uint64_t observed_status) {
  if (observed_status == context->statuses.decoded) {
    return context->destination;
  }

  if (observed_status == context->statuses.decoding) {
    for (;;) {
      observed_status = ObfAtomicLoadU64Acquire(&descriptor->state->status);
      if (observed_status == context->statuses.decoding) {
        continue;
      }
      if (observed_status == context->statuses.decoded) {
        break;
      }
      ObfTrap();
    }

    if (ObfValidateStringDescriptor(context, descriptor, trusted_length, trusted_binding) !=
        context->statuses.decoded) {
      ObfTrap();
    }
    return context->destination;
  }

  ObfTrap();
  return NULL;
}

static uint8_t *ObfHandleConstantPoolObservedStatus(
    struct ObfConstantPoolValidationContext *context,
    const struct ObfConstantPoolRuntimeDescriptorV2 *descriptor,
    uint64_t trusted_length,
    uint64_t trusted_binding,
    uint64_t observed_status) {
  if (observed_status == context->statuses.decoded) {
    return context->destination;
  }

  if (observed_status == context->statuses.decoding) {
    for (;;) {
      observed_status = ObfAtomicLoadU64Acquire(&descriptor->state->status);
      if (observed_status == context->statuses.decoding) {
        continue;
      }
      if (observed_status == context->statuses.decoded) {
        break;
      }
      ObfTrap();
    }

    if (ObfValidateConstantPoolDescriptor(context, descriptor, trusted_length, trusted_binding) !=
        context->statuses.decoded) {
      ObfTrap();
    }
    return context->destination;
  }

  ObfTrap();
  return NULL;
}

__attribute__((visibility("hidden")))
uint8_t *OBF_RT_STRING_AUTH_DECODE_V2(const struct ObfStringRuntimeDescriptorV2 *descriptor,
                                      uint64_t trusted_length,
                                      uint64_t trusted_binding) {
  struct ObfStringValidationContext context;
  uint8_t tag[16];
  uint64_t observed_status;

  observed_status =
      ObfValidateStringDescriptor(&context, descriptor, trusted_length, trusted_binding);
  if (observed_status == context.statuses.cold) {
    uint64_t expected = context.statuses.cold;
    if (ObfAtomicCompareExchangeU64AcquireRelaxed(
            &descriptor->state->status, &expected, context.statuses.decoding)) {
      ObfComputeStringTag(tag, context.mac_key, descriptor, context.length);
      if (!ObfConstantTimeEqual(tag, descriptor->tag, sizeof(tag))) {
        ObfTrap();
      }

      ObfDecodePayload(
          context.destination, context.ciphertext, context.enc_key, descriptor->nonce, context.length);
      ObfAtomicStoreU64Release(&descriptor->state->status, context.statuses.decoded);
      return context.destination;
    }
    return ObfHandleStringObservedStatus(
        &context, descriptor, trusted_length, trusted_binding, expected);
  }

  return ObfHandleStringObservedStatus(
      &context, descriptor, trusted_length, trusted_binding, observed_status);
}

__attribute__((visibility("hidden")))
uint8_t *OBF_RT_CONSTANT_POOL_DECODE_V2(
    const struct ObfConstantPoolRuntimeDescriptorV2 *descriptor,
    uint64_t trusted_length,
    uint64_t trusted_binding) {
  struct ObfConstantPoolValidationContext context;
  uint8_t tag[16];
  uint64_t observed_status;

  observed_status =
      ObfValidateConstantPoolDescriptor(&context, descriptor, trusted_length, trusted_binding);
  if (observed_status == context.statuses.cold) {
    uint64_t expected = context.statuses.cold;
    if (ObfAtomicCompareExchangeU64AcquireRelaxed(
            &descriptor->state->status, &expected, context.statuses.decoding)) {
      ObfComputeConstantPoolTag(tag, context.mac_key, descriptor, context.length);
      if (!ObfConstantTimeEqual(tag, descriptor->tag, sizeof(tag))) {
        ObfTrap();
      }

      ObfDecodePayload(
          context.destination, context.ciphertext, context.enc_key, descriptor->nonce, context.length);
      ObfAtomicStoreU64Release(&descriptor->state->status, context.statuses.decoded);
      return context.destination;
    }
    return ObfHandleConstantPoolObservedStatus(
        &context, descriptor, trusted_length, trusted_binding, expected);
  }

  return ObfHandleConstantPoolObservedStatus(
      &context, descriptor, trusted_length, trusted_binding, observed_status);
}
