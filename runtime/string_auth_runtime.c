#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "obf/support/runtime_abi_generated.h"
#include "obf/support/runtime_atomic.h"
#include "obf/support/blake2s_internal.h"

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
#if defined(__clang__) || defined(__GNUC__)
#define OBF_NORETURN __attribute__((noreturn))
#else
#define OBF_NORETURN
#endif

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

static uint64_t ObfMakeDerivedNonzeroFallback(uint64_t binding_id, uint64_t selector) {
  return (0x9e3779b97f4a7c15ULL ^ binding_id ^ (selector << 32)) | 1ULL;
}

static uint64_t ObfFinalizeDerivedWord(struct ObfBlake2sState *state,
                                       uint64_t binding_id,
                                       uint64_t selector) {
  uint8_t digest[32];
  uint64_t value;
  ObfBlake2sFinal(state, digest);
  value = ObfLoad64(digest);
  ObfSecureZeroize(digest, sizeof(digest));
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
  ObfSecureZeroize(digest, sizeof(digest));
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
  ObfSecureZeroize(digest, sizeof(digest));
}

static int ObfConstantTimeEqual(const uint8_t *lhs, const uint8_t *rhs, size_t size) {
  uint8_t diff = 0;
  size_t index;
  for (index = 0; index < size; ++index) {
    diff |= (uint8_t)(lhs[index] ^ rhs[index]);
  }
  return diff == 0;
}

static OBF_NORETURN void ObfTrap(void) {
#if defined(__clang__) || defined(__GNUC__)
  __builtin_trap();
  __builtin_unreachable();
#else
  abort();
#endif
}

static OBF_NORETURN void ObfTrapAfterZeroize(void *buffer, size_t size) {
  ObfSecureZeroize(buffer, size);
  ObfTrap();
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
    ObfSecureZeroize(block, sizeof(block));
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

static int ObfDeriveRelocationStatuses(struct ObfCacheStatusSet *statuses,
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
    return 0;
  }
  return 1;
}

static int ObfValidateStringDescriptor(
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
    goto failure;
  }
  if (topology->descriptor != descriptor) {
    goto failure;
  }
  if (descriptor->destination == NULL || descriptor->ciphertext == NULL ||
      descriptor->build_key == NULL || descriptor->state == NULL) {
    goto failure;
  }
  if (descriptor->destination != topology->destination_ref ||
      descriptor->ciphertext != topology->ciphertext_ref ||
      descriptor->build_key != topology->build_key_ref ||
      descriptor->state != topology->state_ref ||
      descriptor->destination->target != topology->destination_target ||
      descriptor->ciphertext->target != topology->ciphertext_target ||
      descriptor->build_key->target != topology->build_key_target) {
    goto failure;
  }
  if (descriptor->destination_capacity != topology->destination_capacity ||
      descriptor->ciphertext_capacity != topology->ciphertext_capacity ||
      descriptor->build_key_capacity != topology->build_key_capacity ||
      trusted_length > topology->destination_capacity ||
      trusted_length > topology->ciphertext_capacity ||
      topology->build_key_capacity != kObfBuildKeyBytes) {
    goto failure;
  }
  if (descriptor->version != kObfStringDescriptorVersionV3 ||
      descriptor->flags != kObfStringAuthFlagTrapOnFailure ||
      descriptor->length != trusted_length || trusted_length > (uint64_t)SIZE_MAX) {
    goto failure;
  }

  derived_binding =
      ObfDeriveStringBindingId(descriptor->module_id, descriptor->function_id, descriptor->site_id);
  if (descriptor->binding_id != trusted_binding || descriptor->binding_id != derived_binding) {
    goto failure;
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
    goto failure;
  }
  context->statuses.cold = ObfDeriveCacheColdStatus(context->mac_key,
                                                    kObfAuthDescriptorKindString,
                                                    descriptor->binding_id,
                                                    descriptor->destination_capacity,
                                                    descriptor->ciphertext_capacity,
                                                    descriptor->build_key_capacity);
  ObfSecureZeroize(function_key, sizeof(function_key));
  ObfSecureZeroize(site_key, sizeof(site_key));
  ObfSecureZeroize(&derived_binding, sizeof(derived_binding));
  ObfSecureZeroize(&expected_build_key_cookie, sizeof(expected_build_key_cookie));
  ObfSecureZeroize(&destination_cookie, sizeof(destination_cookie));
  ObfSecureZeroize(&ciphertext_cookie, sizeof(ciphertext_cookie));
  ObfSecureZeroize(&state_cookie, sizeof(state_cookie));
  return 1;

failure:
  ObfSecureZeroize(function_key, sizeof(function_key));
  ObfSecureZeroize(site_key, sizeof(site_key));
  ObfSecureZeroize(&derived_binding, sizeof(derived_binding));
  ObfSecureZeroize(&expected_build_key_cookie, sizeof(expected_build_key_cookie));
  ObfSecureZeroize(&destination_cookie, sizeof(destination_cookie));
  ObfSecureZeroize(&ciphertext_cookie, sizeof(ciphertext_cookie));
  ObfSecureZeroize(&state_cookie, sizeof(state_cookie));
  return 0;
}

static int ObfValidateConstantPoolDescriptor(
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
    goto failure;
  }
  if (topology->descriptor != descriptor) {
    goto failure;
  }
  if (descriptor->destination == NULL || descriptor->ciphertext == NULL ||
      descriptor->build_key == NULL || descriptor->state == NULL) {
    goto failure;
  }
  if (descriptor->destination != topology->destination_ref ||
      descriptor->ciphertext != topology->ciphertext_ref ||
      descriptor->build_key != topology->build_key_ref ||
      descriptor->state != topology->state_ref ||
      descriptor->destination->target != topology->destination_target ||
      descriptor->ciphertext->target != topology->ciphertext_target ||
      descriptor->build_key->target != topology->build_key_target) {
    goto failure;
  }
  if (descriptor->destination_capacity != topology->destination_capacity ||
      descriptor->ciphertext_capacity != topology->ciphertext_capacity ||
      descriptor->build_key_capacity != topology->build_key_capacity ||
      trusted_length > topology->destination_capacity ||
      trusted_length > topology->ciphertext_capacity ||
      topology->build_key_capacity != kObfBuildKeyBytes) {
    goto failure;
  }
  if (descriptor->version != kObfConstantPoolDescriptorVersionV3 ||
      descriptor->flags != kObfConstantPoolAuthFlagTrapOnFailure ||
      descriptor->length != trusted_length || trusted_length > (uint64_t)SIZE_MAX) {
    goto failure;
  }

  derived_binding = ObfDeriveConstantPoolBindingId(descriptor->module_id, descriptor->pool_id);
  if (descriptor->binding_id != trusted_binding || descriptor->binding_id != derived_binding) {
    goto failure;
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
    goto failure;
  }
  context->statuses.cold = ObfDeriveCacheColdStatus(context->mac_key,
                                                    kObfAuthDescriptorKindConstantPool,
                                                    descriptor->binding_id,
                                                    descriptor->destination_capacity,
                                                    descriptor->ciphertext_capacity,
                                                    descriptor->build_key_capacity);
  ObfSecureZeroize(function_key, sizeof(function_key));
  ObfSecureZeroize(pool_key, sizeof(pool_key));
  ObfSecureZeroize(&derived_binding, sizeof(derived_binding));
  ObfSecureZeroize(&expected_build_key_cookie, sizeof(expected_build_key_cookie));
  ObfSecureZeroize(&destination_cookie, sizeof(destination_cookie));
  ObfSecureZeroize(&ciphertext_cookie, sizeof(ciphertext_cookie));
  ObfSecureZeroize(&state_cookie, sizeof(state_cookie));
  return 1;

failure:
  ObfSecureZeroize(function_key, sizeof(function_key));
  ObfSecureZeroize(pool_key, sizeof(pool_key));
  ObfSecureZeroize(&derived_binding, sizeof(derived_binding));
  ObfSecureZeroize(&expected_build_key_cookie, sizeof(expected_build_key_cookie));
  ObfSecureZeroize(&destination_cookie, sizeof(destination_cookie));
  ObfSecureZeroize(&ciphertext_cookie, sizeof(ciphertext_cookie));
  ObfSecureZeroize(&state_cookie, sizeof(state_cookie));
  return 0;
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
  uint64_t value;
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
  value = ObfNormalizeDerivedWord(ObfLoad64(digest), binding_id, (uint64_t)length);
  ObfSecureZeroize(digest, sizeof(digest));
  return value;
}

static int ObfVerifyStringTag(const struct ObfStringValidationContext *context,
                              const struct ObfStringRuntimeDescriptorV3 *descriptor) {
  uint8_t tag[16];
  const int valid =
      (ObfComputeStringTag(tag, context->mac_key, descriptor, context->ciphertext, context->length),
       ObfConstantTimeEqual(tag, descriptor->tag, sizeof(tag)));
  ObfSecureZeroize(tag, sizeof(tag));
  return valid;
}

static int ObfVerifyConstantPoolTag(
    const struct ObfConstantPoolValidationContext *context,
    const struct ObfConstantPoolRuntimeDescriptorV3 *descriptor) {
  uint8_t tag[16];
  const int valid =
      (ObfComputeConstantPoolTag(
           tag, context->mac_key, descriptor, context->ciphertext, context->length),
       ObfConstantTimeEqual(tag, descriptor->tag, sizeof(tag)));
  ObfSecureZeroize(tag, sizeof(tag));
  return valid;
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
    if (!ObfVerifyStringTag(context, descriptor)) {
      ObfTrapAfterZeroize(context, sizeof(*context));
    }
    if (status == context->statuses.decoded) {
      const uint64_t expected_completion = ObfStringCompletion(context, descriptor, topology);
      if (completion != expected_completion) {
        ObfTrapAfterZeroize(context, sizeof(*context));
      }
      uint8_t *destination = context->destination;
      ObfSecureZeroize(context, sizeof(*context));
      return destination;
    }
    if ((status == context->statuses.cold && completion == context->statuses.decoding) ||
        (status == context->statuses.decoding && completion == context->statuses.decoding)) {
      continue;
    }
    ObfTrapAfterZeroize(context, sizeof(*context));
  }
  ObfTrapAfterZeroize(context, sizeof(*context));
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
    if (!ObfVerifyConstantPoolTag(context, descriptor)) {
      ObfTrapAfterZeroize(context, sizeof(*context));
    }
    if (status == context->statuses.decoded) {
      const uint64_t expected_completion = ObfConstantPoolCompletion(context, descriptor, topology);
      if (completion != expected_completion) {
        ObfTrapAfterZeroize(context, sizeof(*context));
      }
      uint8_t *destination = context->destination;
      ObfSecureZeroize(context, sizeof(*context));
      return destination;
    }
    if ((status == context->statuses.cold && completion == context->statuses.decoding) ||
        (status == context->statuses.decoding && completion == context->statuses.decoding)) {
      continue;
    }
    ObfTrapAfterZeroize(context, sizeof(*context));
  }
  ObfTrapAfterZeroize(context, sizeof(*context));
  return NULL;
}

__attribute__((visibility("hidden")))
uint8_t *OBF_RT_STRING_AUTH_DECODE_V3(
    const struct ObfStringRuntimeDescriptorV3 *descriptor,
    uint64_t trusted_length,
    uint64_t trusted_binding,
    const struct ObfAuthenticatedDecodeTopologyV3 *trusted_topology) {
  struct ObfStringValidationContext context;
  if (!ObfValidateStringDescriptor(
          &context, descriptor, trusted_length, trusted_binding, trusted_topology)) {
    ObfTrapAfterZeroize(&context, sizeof(context));
  }
  if (!ObfVerifyStringTag(&context, descriptor)) {
    ObfTrapAfterZeroize(&context, sizeof(context));
  }
  if (!ObfDeriveRelocationStatuses(&context.statuses,
                                   context.mac_key,
                                   kObfAuthDescriptorKindString,
                                   descriptor->binding_id,
                                   descriptor,
                                   trusted_topology,
                                   descriptor->state)) {
    ObfTrapAfterZeroize(&context, sizeof(context));
  }

  for (uint32_t poll = 0; poll < kObfDecodePollLimit; ++poll) {
    if (!ObfVerifyStringTag(&context, descriptor)) {
      ObfTrapAfterZeroize(&context, sizeof(context));
    }
    const uint64_t status = ObfAtomicLoadU64Acquire(&descriptor->state->status);
    const uint64_t completion = ObfAtomicLoadU64Acquire(&descriptor->state->completion);
    if (status == context.statuses.decoded) {
      const uint64_t expected_completion = ObfStringCompletion(&context, descriptor, trusted_topology);
      if (!ObfVerifyStringTag(&context, descriptor)) {
        ObfTrapAfterZeroize(&context, sizeof(context));
      }
      if (completion != expected_completion) {
        ObfTrapAfterZeroize(&context, sizeof(context));
      }
      uint8_t *destination = context.destination;
      ObfSecureZeroize(&context, sizeof(context));
      return destination;
    }
    if (status == context.statuses.cold && completion == context.statuses.cold) {
      uint64_t expected = context.statuses.cold;
      if (ObfAtomicCompareExchangeU64AcqRelRelaxed(
              &descriptor->state->completion, &expected, context.statuses.decoding)) {
        ObfAtomicStoreU64Release(&descriptor->state->status, context.statuses.decoding);
        if (!ObfVerifyStringTag(&context, descriptor)) {
          ObfTrapAfterZeroize(&context, sizeof(context));
        }
        ObfDecodePayload(
            context.destination, context.ciphertext, context.enc_key, descriptor->nonce, context.length);
        const uint64_t decoded_completion =
            ObfStringCompletion(&context, descriptor, trusted_topology);
        ObfAtomicStoreU64Release(&descriptor->state->completion, decoded_completion);
        ObfAtomicStoreU64Release(&descriptor->state->status, context.statuses.decoded);
        uint8_t *destination = context.destination;
        ObfSecureZeroize(&context, sizeof(context));
        return destination;
      }
      continue;
    }
    if ((status == context.statuses.cold && completion == context.statuses.decoding) ||
        (status == context.statuses.decoding && completion == context.statuses.decoding)) {
      return ObfWaitForStringDecode(&context, descriptor, trusted_topology);
    }
    ObfTrapAfterZeroize(&context, sizeof(context));
  }
  ObfTrapAfterZeroize(&context, sizeof(context));
  return NULL;
}

__attribute__((visibility("hidden")))
uint8_t *OBF_RT_CONSTANT_POOL_DECODE_V3(
    const struct ObfConstantPoolRuntimeDescriptorV3 *descriptor,
    uint64_t trusted_length,
    uint64_t trusted_binding,
    const struct ObfAuthenticatedDecodeTopologyV3 *trusted_topology) {
  struct ObfConstantPoolValidationContext context;
  if (!ObfValidateConstantPoolDescriptor(
          &context, descriptor, trusted_length, trusted_binding, trusted_topology)) {
    ObfTrapAfterZeroize(&context, sizeof(context));
  }
  if (!ObfVerifyConstantPoolTag(&context, descriptor)) {
    ObfTrapAfterZeroize(&context, sizeof(context));
  }
  if (!ObfDeriveRelocationStatuses(&context.statuses,
                                   context.mac_key,
                                   kObfAuthDescriptorKindConstantPool,
                                   descriptor->binding_id,
                                   descriptor,
                                   trusted_topology,
                                   descriptor->state)) {
    ObfTrapAfterZeroize(&context, sizeof(context));
  }

  for (uint32_t poll = 0; poll < kObfDecodePollLimit; ++poll) {
    if (!ObfVerifyConstantPoolTag(&context, descriptor)) {
      ObfTrapAfterZeroize(&context, sizeof(context));
    }
    const uint64_t status = ObfAtomicLoadU64Acquire(&descriptor->state->status);
    const uint64_t completion = ObfAtomicLoadU64Acquire(&descriptor->state->completion);
    if (status == context.statuses.decoded) {
      const uint64_t expected_completion =
          ObfConstantPoolCompletion(&context, descriptor, trusted_topology);
      if (!ObfVerifyConstantPoolTag(&context, descriptor)) {
        ObfTrapAfterZeroize(&context, sizeof(context));
      }
      if (completion != expected_completion) {
        ObfTrapAfterZeroize(&context, sizeof(context));
      }
      uint8_t *destination = context.destination;
      ObfSecureZeroize(&context, sizeof(context));
      return destination;
    }
    if (status == context.statuses.cold && completion == context.statuses.cold) {
      uint64_t expected = context.statuses.cold;
      if (ObfAtomicCompareExchangeU64AcqRelRelaxed(
              &descriptor->state->completion, &expected, context.statuses.decoding)) {
        ObfAtomicStoreU64Release(&descriptor->state->status, context.statuses.decoding);
        if (!ObfVerifyConstantPoolTag(&context, descriptor)) {
          ObfTrapAfterZeroize(&context, sizeof(context));
        }
        ObfDecodePayload(
            context.destination, context.ciphertext, context.enc_key, descriptor->nonce, context.length);
        const uint64_t decoded_completion =
            ObfConstantPoolCompletion(&context, descriptor, trusted_topology);
        ObfAtomicStoreU64Release(&descriptor->state->completion, decoded_completion);
        ObfAtomicStoreU64Release(&descriptor->state->status, context.statuses.decoded);
        uint8_t *destination = context.destination;
        ObfSecureZeroize(&context, sizeof(context));
        return destination;
      }
      continue;
    }
    if ((status == context.statuses.cold && completion == context.statuses.decoding) ||
        (status == context.statuses.decoding && completion == context.statuses.decoding)) {
      return ObfWaitForConstantPoolDecode(&context, descriptor, trusted_topology);
    }
    ObfTrapAfterZeroize(&context, sizeof(context));
  }
  ObfTrapAfterZeroize(&context, sizeof(context));
  return NULL;
}
