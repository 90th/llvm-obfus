#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <type_traits>

#include "obf/support/runtime_abi_generated.h"

namespace obf::auth {

inline constexpr std::size_t kBlake2sBlockBytes = 64;
inline constexpr std::size_t kBlake2sOutBytes = 32;
inline constexpr std::size_t kBuildKeyBytes = 32;
inline constexpr std::size_t kStringNonceBytes = 16;
inline constexpr std::size_t kStringTagBytes = 16;
inline constexpr std::uint32_t kStringDescriptorVersionV2 = 2;
inline constexpr std::uint32_t kStringAuthFlagTrapOnFailure = 1U;
inline constexpr std::uint32_t kConstantPoolDescriptorVersionV2 = 2;
inline constexpr std::uint32_t kConstantPoolAuthFlagTrapOnFailure = 1U;

using Blake2sDigest = std::array<std::uint8_t, kBlake2sOutBytes>;
using BuildKey = std::array<std::uint8_t, kBuildKeyBytes>;
using StringNonce = std::array<std::uint8_t, kStringNonceBytes>;
using StringTag = std::array<std::uint8_t, kStringTagBytes>;

enum class AuthDescriptorKind : std::uint32_t {
  string = 1,
  constant_pool = 2,
};

enum class AuthReferenceRole : std::uint32_t {
  destination = 1,
  ciphertext = 2,
  build_key = 3,
  state = 4,
};

enum class CacheStatusKind : std::uint32_t {
  cold = 0,
  decoding = 1,
  decoded = 2,
};

struct AuthenticatedBufferReferenceV2 {
  std::uint64_t cookie = 0;
  std::uint8_t* target = nullptr;
};

struct AuthenticatedStateReferenceV2 {
  std::uint64_t cookie = 0;
  std::uint64_t status = 0;
};

struct StringAuthMetadata {
  std::uint32_t version = kStringDescriptorVersionV2;
  std::uint32_t flags = kStringAuthFlagTrapOnFailure;
  std::uint64_t length = 0;
  std::uint64_t module_id = 0;
  std::uint64_t function_id = 0;
  std::uint64_t site_id = 0;
  std::uint64_t binding_id = 0;
  std::uint64_t destination_cookie = 0;
  std::uint64_t ciphertext_cookie = 0;
  std::uint64_t build_key_cookie = 0;
  std::uint64_t state_cookie = 0;
  StringNonce nonce{};
};

struct Blake2sState {
  std::array<std::uint32_t, 8> h{};
  std::array<std::uint32_t, 2> t{};
  std::array<std::uint32_t, 2> f{};
  std::array<std::uint8_t, kBlake2sBlockBytes> buf{};
  std::size_t buflen = 0;
  std::size_t outlen = kBlake2sOutBytes;
};

inline constexpr std::array<std::uint32_t, 8> kBlake2sIv = {
    0x6a09e667U,
    0xbb67ae85U,
    0x3c6ef372U,
    0xa54ff53aU,
    0x510e527fU,
    0x9b05688cU,
    0x1f83d9abU,
    0x5be0cd19U,
};

inline constexpr std::array<std::array<std::uint8_t, 16>, 10> kBlake2sSigma = {{
    {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
    {{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}},
    {{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}},
    {{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8}},
    {{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}},
    {{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9}},
    {{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}},
    {{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10}},
    {{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}},
    {{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}},
}};

inline constexpr std::array<std::uint8_t, 2> kDomainFunction = {'f', 'n'};
inline constexpr std::array<std::uint8_t, 5> kDomainBuild = {'b', 'u', 'i', 'l', 'd'};
inline constexpr std::array<std::uint8_t, 6> kDomainString = {'s', 't', 'r', 'i', 'n', 'g'};
inline constexpr std::array<std::uint8_t, 5> kDomainConstant = {'c', 'o', 'n', 's', 't'};
inline constexpr std::array<std::uint8_t, 3> kDomainEnc = {'e', 'n', 'c'};
inline constexpr std::array<std::uint8_t, 3> kDomainMac = {'m', 'a', 'c'};
inline constexpr std::array<std::uint8_t, 5> kDomainNonce = {'n', 'o', 'n', 'c', 'e'};
inline constexpr std::array<std::uint8_t, 6> kDomainStream = {'s', 't', 'r', 'e', 'a', 'm'};
inline constexpr std::array<std::uint8_t, 10> kDomainStringTag = {
    's', 't', 'r', 'i', 'n', 'g', '_', 't', 'a', 'g'};
inline constexpr std::array<std::uint8_t, 14> kDomainConstantPoolTag = {
    'c', 'o', 'n', 's', 't', '_', 'p', 'o', 'o', 'l', '_', 't', 'a', 'g'};
inline constexpr std::array<std::uint8_t, 17> kDomainStringBindingV2 = {
    's', 't', 'r', 'i', 'n', 'g', '_', 'b', 'i', 'n', 'd', 'i', 'n', 'g', '_', 'v', '2'};
inline constexpr std::array<std::uint8_t, 19> kDomainConstantBindingV2 = {
    'c', 'o', 'n', 's', 't', 'a', 'n', 't', '_', 'b', 'i', 'n', 'd', 'i', 'n', 'g', '_', 'v', '2'};
inline constexpr std::array<std::uint8_t, 19> kDomainReferenceCookieV2 = {
    'r', 'e', 'f', 'e', 'r', 'e', 'n', 'c', 'e', '_', 'c', 'o', 'o', 'k', 'i', 'e', '_', 'v', '2'};
inline constexpr std::array<std::uint8_t, 19> kDomainBuildKeyCookieV2 = {
    'b', 'u', 'i', 'l', 'd', '_', 'k', 'e', 'y', '_', 'c', 'o', 'o', 'k', 'i', 'e', '_', 'v', '2'};
inline constexpr std::array<std::uint8_t, 15> kDomainCacheStatusV2 = {
    'c', 'a', 'c', 'h', 'e', '_', 's', 't', 'a', 't', 'u', 's', '_', 'v', '2'};
inline constexpr std::string_view kRuntimeStringDecodeSymbolV2 = OBF_RT_STRING_AUTH_DECODE_V2_STR;
inline constexpr std::string_view kRuntimeConstantPoolDecodeSymbolV2 =
    OBF_RT_CONSTANT_POOL_DECODE_V2_STR;

struct StringRuntimeDescriptorV2 {
  std::uint32_t version = kStringDescriptorVersionV2;
  std::uint32_t flags = kStringAuthFlagTrapOnFailure;
  std::uint64_t length = 0;
  std::uint64_t module_id = 0;
  std::uint64_t function_id = 0;
  std::uint64_t site_id = 0;
  std::uint64_t binding_id = 0;
  std::uint64_t destination_cookie = 0;
  std::uint64_t ciphertext_cookie = 0;
  std::uint64_t build_key_cookie = 0;
  std::uint64_t state_cookie = 0;
  StringNonce nonce{};
  StringTag tag{};
  AuthenticatedBufferReferenceV2* destination = nullptr;
  const AuthenticatedBufferReferenceV2* ciphertext = nullptr;
  const AuthenticatedBufferReferenceV2* build_key = nullptr;
  AuthenticatedStateReferenceV2* state = nullptr;
};

struct ConstantPoolAuthMetadata {
  std::uint32_t version = kConstantPoolDescriptorVersionV2;
  std::uint32_t flags = kConstantPoolAuthFlagTrapOnFailure;
  std::uint64_t length = 0;
  std::uint64_t module_id = 0;
  std::uint64_t pool_id = 0;
  std::uint64_t binding_id = 0;
  std::uint64_t destination_cookie = 0;
  std::uint64_t ciphertext_cookie = 0;
  std::uint64_t build_key_cookie = 0;
  std::uint64_t state_cookie = 0;
  StringNonce nonce{};
};

struct ConstantPoolRuntimeDescriptorV2 {
  std::uint32_t version = kConstantPoolDescriptorVersionV2;
  std::uint32_t flags = kConstantPoolAuthFlagTrapOnFailure;
  std::uint64_t length = 0;
  std::uint64_t module_id = 0;
  std::uint64_t pool_id = 0;
  std::uint64_t binding_id = 0;
  std::uint64_t destination_cookie = 0;
  std::uint64_t ciphertext_cookie = 0;
  std::uint64_t build_key_cookie = 0;
  std::uint64_t state_cookie = 0;
  StringNonce nonce{};
  StringTag tag{};
  AuthenticatedBufferReferenceV2* destination = nullptr;
  const AuthenticatedBufferReferenceV2* ciphertext = nullptr;
  const AuthenticatedBufferReferenceV2* build_key = nullptr;
  AuthenticatedStateReferenceV2* state = nullptr;
};

constexpr std::size_t MaxSize(std::size_t lhs, std::size_t rhs) {
  return lhs < rhs ? rhs : lhs;
}

constexpr std::size_t RoundUpSize(std::size_t value, std::size_t alignment) {
  return ((value + alignment - 1) / alignment) * alignment;
}

constexpr std::uint64_t MakeDerivedNonzeroFallback(std::uint64_t binding_id,
                                                   std::uint64_t selector) {
  return (0x9e3779b97f4a7c15ULL ^ binding_id ^ (selector << 32)) | 1ULL;
}

static_assert(std::is_standard_layout_v<AuthenticatedBufferReferenceV2>);
static_assert(std::is_standard_layout_v<AuthenticatedStateReferenceV2>);
static_assert(std::is_standard_layout_v<StringRuntimeDescriptorV2>);
static_assert(std::is_standard_layout_v<ConstantPoolRuntimeDescriptorV2>);
static_assert(offsetof(AuthenticatedBufferReferenceV2, cookie) == 0);
static_assert(offsetof(AuthenticatedBufferReferenceV2, target) ==
              RoundUpSize(sizeof(std::uint64_t), alignof(std::uint8_t*)));
static_assert(sizeof(AuthenticatedBufferReferenceV2) ==
              RoundUpSize(offsetof(AuthenticatedBufferReferenceV2, target) +
                              sizeof(AuthenticatedBufferReferenceV2::target),
                          alignof(AuthenticatedBufferReferenceV2)));
static_assert(alignof(AuthenticatedBufferReferenceV2) ==
              MaxSize(alignof(std::uint64_t), alignof(std::uint8_t*)));
static_assert(offsetof(AuthenticatedStateReferenceV2, cookie) == 0);
static_assert(offsetof(AuthenticatedStateReferenceV2, status) ==
              RoundUpSize(sizeof(std::uint64_t), alignof(std::uint64_t)));
static_assert(sizeof(AuthenticatedStateReferenceV2) ==
              RoundUpSize(offsetof(AuthenticatedStateReferenceV2, status) +
                              sizeof(AuthenticatedStateReferenceV2::status),
                          alignof(AuthenticatedStateReferenceV2)));
static_assert(alignof(AuthenticatedStateReferenceV2) == alignof(std::uint64_t));
static_assert(offsetof(StringRuntimeDescriptorV2, version) == 0);
static_assert(offsetof(StringRuntimeDescriptorV2, flags) == sizeof(std::uint32_t));
static_assert(offsetof(StringRuntimeDescriptorV2, length) == sizeof(std::uint64_t));
static_assert(offsetof(StringRuntimeDescriptorV2, module_id) ==
              offsetof(StringRuntimeDescriptorV2, length) + sizeof(StringRuntimeDescriptorV2::length));
static_assert(offsetof(StringRuntimeDescriptorV2, function_id) ==
              offsetof(StringRuntimeDescriptorV2, module_id) + sizeof(StringRuntimeDescriptorV2::module_id));
static_assert(offsetof(StringRuntimeDescriptorV2, site_id) ==
              offsetof(StringRuntimeDescriptorV2, function_id) + sizeof(StringRuntimeDescriptorV2::function_id));
static_assert(offsetof(StringRuntimeDescriptorV2, binding_id) ==
              offsetof(StringRuntimeDescriptorV2, site_id) + sizeof(StringRuntimeDescriptorV2::site_id));
static_assert(offsetof(StringRuntimeDescriptorV2, destination_cookie) ==
              offsetof(StringRuntimeDescriptorV2, binding_id) +
                  sizeof(StringRuntimeDescriptorV2::binding_id));
static_assert(offsetof(StringRuntimeDescriptorV2, ciphertext_cookie) ==
              offsetof(StringRuntimeDescriptorV2, destination_cookie) +
                  sizeof(StringRuntimeDescriptorV2::destination_cookie));
static_assert(offsetof(StringRuntimeDescriptorV2, build_key_cookie) ==
              offsetof(StringRuntimeDescriptorV2, ciphertext_cookie) +
                  sizeof(StringRuntimeDescriptorV2::ciphertext_cookie));
static_assert(offsetof(StringRuntimeDescriptorV2, state_cookie) ==
              offsetof(StringRuntimeDescriptorV2, build_key_cookie) +
                  sizeof(StringRuntimeDescriptorV2::build_key_cookie));
static_assert(offsetof(StringRuntimeDescriptorV2, nonce) ==
              offsetof(StringRuntimeDescriptorV2, state_cookie) +
                  sizeof(StringRuntimeDescriptorV2::state_cookie));
static_assert(offsetof(StringRuntimeDescriptorV2, tag) ==
              offsetof(StringRuntimeDescriptorV2, nonce) + sizeof(StringRuntimeDescriptorV2::nonce));
static_assert(offsetof(StringRuntimeDescriptorV2, destination) ==
              offsetof(StringRuntimeDescriptorV2, tag) + sizeof(StringRuntimeDescriptorV2::tag));
static_assert(offsetof(StringRuntimeDescriptorV2, destination) % alignof(AuthenticatedBufferReferenceV2*) ==
              0);
static_assert(offsetof(StringRuntimeDescriptorV2, ciphertext) ==
              offsetof(StringRuntimeDescriptorV2, destination) +
                  sizeof(StringRuntimeDescriptorV2::destination));
static_assert(offsetof(StringRuntimeDescriptorV2, build_key) ==
              offsetof(StringRuntimeDescriptorV2, ciphertext) +
                  sizeof(StringRuntimeDescriptorV2::ciphertext));
static_assert(offsetof(StringRuntimeDescriptorV2, state) ==
              offsetof(StringRuntimeDescriptorV2, build_key) +
                  sizeof(StringRuntimeDescriptorV2::build_key));
static_assert(offsetof(ConstantPoolRuntimeDescriptorV2, version) == 0);
static_assert(offsetof(ConstantPoolRuntimeDescriptorV2, flags) == sizeof(std::uint32_t));
static_assert(offsetof(ConstantPoolRuntimeDescriptorV2, length) == sizeof(std::uint64_t));
static_assert(offsetof(ConstantPoolRuntimeDescriptorV2, module_id) ==
              offsetof(ConstantPoolRuntimeDescriptorV2, length) +
                  sizeof(ConstantPoolRuntimeDescriptorV2::length));
static_assert(offsetof(ConstantPoolRuntimeDescriptorV2, pool_id) ==
              offsetof(ConstantPoolRuntimeDescriptorV2, module_id) +
                  sizeof(ConstantPoolRuntimeDescriptorV2::module_id));
static_assert(offsetof(ConstantPoolRuntimeDescriptorV2, binding_id) ==
              offsetof(ConstantPoolRuntimeDescriptorV2, pool_id) +
                  sizeof(ConstantPoolRuntimeDescriptorV2::pool_id));
static_assert(offsetof(ConstantPoolRuntimeDescriptorV2, destination_cookie) ==
              offsetof(ConstantPoolRuntimeDescriptorV2, binding_id) +
                  sizeof(ConstantPoolRuntimeDescriptorV2::binding_id));
static_assert(offsetof(ConstantPoolRuntimeDescriptorV2, ciphertext_cookie) ==
              offsetof(ConstantPoolRuntimeDescriptorV2, destination_cookie) +
                  sizeof(ConstantPoolRuntimeDescriptorV2::destination_cookie));
static_assert(offsetof(ConstantPoolRuntimeDescriptorV2, build_key_cookie) ==
              offsetof(ConstantPoolRuntimeDescriptorV2, ciphertext_cookie) +
                  sizeof(ConstantPoolRuntimeDescriptorV2::ciphertext_cookie));
static_assert(offsetof(ConstantPoolRuntimeDescriptorV2, state_cookie) ==
              offsetof(ConstantPoolRuntimeDescriptorV2, build_key_cookie) +
                  sizeof(ConstantPoolRuntimeDescriptorV2::build_key_cookie));
static_assert(offsetof(ConstantPoolRuntimeDescriptorV2, nonce) ==
              offsetof(ConstantPoolRuntimeDescriptorV2, state_cookie) +
                  sizeof(ConstantPoolRuntimeDescriptorV2::state_cookie));
static_assert(offsetof(ConstantPoolRuntimeDescriptorV2, tag) ==
              offsetof(ConstantPoolRuntimeDescriptorV2, nonce) +
                  sizeof(ConstantPoolRuntimeDescriptorV2::nonce));
static_assert(offsetof(ConstantPoolRuntimeDescriptorV2, destination) ==
              offsetof(ConstantPoolRuntimeDescriptorV2, tag) +
                  sizeof(ConstantPoolRuntimeDescriptorV2::tag));
static_assert(offsetof(ConstantPoolRuntimeDescriptorV2, destination) %
                  alignof(AuthenticatedBufferReferenceV2*) ==
              0);
static_assert(offsetof(ConstantPoolRuntimeDescriptorV2, ciphertext) ==
              offsetof(ConstantPoolRuntimeDescriptorV2, destination) +
                  sizeof(ConstantPoolRuntimeDescriptorV2::destination));
static_assert(offsetof(ConstantPoolRuntimeDescriptorV2, build_key) ==
              offsetof(ConstantPoolRuntimeDescriptorV2, ciphertext) +
                  sizeof(ConstantPoolRuntimeDescriptorV2::ciphertext));
static_assert(offsetof(ConstantPoolRuntimeDescriptorV2, state) ==
              offsetof(ConstantPoolRuntimeDescriptorV2, build_key) +
                  sizeof(ConstantPoolRuntimeDescriptorV2::build_key));

inline std::uint32_t Load32(std::span<const std::uint8_t> input, std::size_t offset) {
  return static_cast<std::uint32_t>(input[offset]) |
         (static_cast<std::uint32_t>(input[offset + 1]) << 8) |
         (static_cast<std::uint32_t>(input[offset + 2]) << 16) |
         (static_cast<std::uint32_t>(input[offset + 3]) << 24);
}

inline void Store32(std::uint32_t value, std::uint8_t* output) {
  output[0] = static_cast<std::uint8_t>(value);
  output[1] = static_cast<std::uint8_t>(value >> 8);
  output[2] = static_cast<std::uint8_t>(value >> 16);
  output[3] = static_cast<std::uint8_t>(value >> 24);
}

inline void Store64(std::uint64_t value, std::uint8_t* output) {
  for (unsigned index = 0; index < 8; ++index) {
    output[index] = static_cast<std::uint8_t>(value >> (index * 8));
  }
}

inline std::uint64_t Load64(const std::uint8_t* input) {
  std::uint64_t value = 0;
  for (unsigned index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(input[index]) << (index * 8);
  }
  return value;
}

inline std::uint32_t RotateRight(std::uint32_t value, unsigned amount) {
  return (value >> amount) | (value << (32U - amount));
}

inline void Blake2sMix(std::array<std::uint32_t, 16>& v,
                       unsigned a,
                       unsigned b,
                       unsigned c,
                       unsigned d,
                       std::uint32_t x,
                       std::uint32_t y) {
  v[a] = v[a] + v[b] + x;
  v[d] = RotateRight(v[d] ^ v[a], 16);
  v[c] = v[c] + v[d];
  v[b] = RotateRight(v[b] ^ v[c], 12);
  v[a] = v[a] + v[b] + y;
  v[d] = RotateRight(v[d] ^ v[a], 8);
  v[c] = v[c] + v[d];
  v[b] = RotateRight(v[b] ^ v[c], 7);
}

inline void Blake2sCompress(Blake2sState& state, const std::uint8_t block[kBlake2sBlockBytes]) {
  std::array<std::uint32_t, 16> m{};
  std::array<std::uint32_t, 16> v{};

  for (unsigned index = 0; index < 16; ++index) {
    m[index] = Load32(std::span<const std::uint8_t>(block, kBlake2sBlockBytes), index * 4);
  }

  for (unsigned index = 0; index < 8; ++index) {
    v[index] = state.h[index];
    v[index + 8] = kBlake2sIv[index];
  }

  v[12] ^= state.t[0];
  v[13] ^= state.t[1];
  v[14] ^= state.f[0];
  v[15] ^= state.f[1];

  for (unsigned round = 0; round < 10; ++round) {
    const auto& sigma = kBlake2sSigma[round];
    Blake2sMix(v, 0, 4, 8, 12, m[sigma[0]], m[sigma[1]]);
    Blake2sMix(v, 1, 5, 9, 13, m[sigma[2]], m[sigma[3]]);
    Blake2sMix(v, 2, 6, 10, 14, m[sigma[4]], m[sigma[5]]);
    Blake2sMix(v, 3, 7, 11, 15, m[sigma[6]], m[sigma[7]]);
    Blake2sMix(v, 0, 5, 10, 15, m[sigma[8]], m[sigma[9]]);
    Blake2sMix(v, 1, 6, 11, 12, m[sigma[10]], m[sigma[11]]);
    Blake2sMix(v, 2, 7, 8, 13, m[sigma[12]], m[sigma[13]]);
    Blake2sMix(v, 3, 4, 9, 14, m[sigma[14]], m[sigma[15]]);
  }

  for (unsigned index = 0; index < 8; ++index) {
    state.h[index] ^= v[index] ^ v[index + 8];
  }
}

inline bool Blake2sInit(Blake2sState& state,
                        std::size_t output_size,
                        std::span<const std::uint8_t> key = {}) {
  if (output_size == 0 || output_size > kBlake2sOutBytes || key.size() > kBlake2sOutBytes) {
    return false;
  }

  state = {};
  state.outlen = output_size;
  state.h = kBlake2sIv;
  state.h[0] ^=
      (0x01010000U ^ (static_cast<std::uint32_t>(key.size()) << 8)) |
      static_cast<std::uint32_t>(output_size);

  if (!key.empty()) {
    std::array<std::uint8_t, kBlake2sBlockBytes> block{};
    std::memcpy(block.data(), key.data(), key.size());
    state.buf = block;
    state.buflen = kBlake2sBlockBytes;
  }

  return true;
}

inline void Blake2sIncrement(Blake2sState& state, std::size_t count) {
  state.t[0] += static_cast<std::uint32_t>(count);
  state.t[1] += static_cast<std::uint32_t>(state.t[0] < count);
}

inline void Blake2sUpdate(Blake2sState& state, std::span<const std::uint8_t> input) {
  if (input.empty()) { return; }

  std::size_t offset = 0;
  if (state.buflen == kBlake2sBlockBytes) {
    Blake2sIncrement(state, kBlake2sBlockBytes);
    Blake2sCompress(state, state.buf.data());
    state.buf.fill(0);
    state.buflen = 0;
  }

  while (offset < input.size()) {
    const std::size_t available = kBlake2sBlockBytes - state.buflen;
    const std::size_t to_copy = std::min(available, input.size() - offset);
    std::memcpy(state.buf.data() + state.buflen, input.data() + offset, to_copy);
    state.buflen += to_copy;
    offset += to_copy;

    if (state.buflen == kBlake2sBlockBytes && offset < input.size()) {
      Blake2sIncrement(state, kBlake2sBlockBytes);
      Blake2sCompress(state, state.buf.data());
      state.buf.fill(0);
      state.buflen = 0;
    }
  }
}

inline Blake2sDigest Blake2sFinal(Blake2sState& state) {
  Blake2sIncrement(state, state.buflen);
  state.f[0] = 0xffffffffU;
  for (std::size_t index = state.buflen; index < kBlake2sBlockBytes; ++index) {
    state.buf[index] = 0;
  }
  Blake2sCompress(state, state.buf.data());

  Blake2sDigest digest{};
  for (unsigned index = 0; index < 8; ++index) {
    Store32(state.h[index], digest.data() + (index * 4));
  }
  return digest;
}

inline Blake2sDigest Blake2s(std::span<const std::uint8_t> input,
                             std::span<const std::uint8_t> key = {}) {
  Blake2sState state{};
  if (!Blake2sInit(state, kBlake2sOutBytes, key)) { return {}; }
  Blake2sUpdate(state, input);
  return Blake2sFinal(state);
}

inline void Blake2sUpdateU32(Blake2sState& state, std::uint32_t value) {
  std::array<std::uint8_t, 4> bytes{};
  Store32(value, bytes.data());
  Blake2sUpdate(state, bytes);
}

inline void Blake2sUpdateU64(Blake2sState& state, std::uint64_t value) {
  std::array<std::uint8_t, 8> bytes{};
  Store64(value, bytes.data());
  Blake2sUpdate(state, bytes);
}

inline void Blake2sUpdateDomain(Blake2sState& state, std::span<const std::uint8_t> domain) {
  Blake2sUpdateU32(state, static_cast<std::uint32_t>(domain.size()));
  Blake2sUpdate(state, domain);
}

inline std::uint64_t FinalizeDerivedWord(Blake2sState& state,
                                         std::uint64_t binding_id,
                                         std::uint64_t selector) {
  const Blake2sDigest digest = Blake2sFinal(state);
  const std::uint64_t value = Load64(digest.data());
  return value == 0 ? MakeDerivedNonzeroFallback(binding_id, selector) : value;
}

inline std::uint64_t NormalizeDerivedWord(std::uint64_t value,
                                          std::uint64_t binding_id,
                                          std::uint64_t selector) {
  return value == 0 ? MakeDerivedNonzeroFallback(binding_id, selector) : value;
}

inline std::uint64_t DeriveStringBindingId(std::uint64_t module_id,
                                           std::uint64_t function_id,
                                           std::uint64_t site_id) {
  Blake2sState state;
  Blake2sInit(state, kBlake2sOutBytes);
  Blake2sUpdateDomain(state, kDomainStringBindingV2);
  Blake2sUpdateU64(state, module_id);
  Blake2sUpdateU64(state, function_id);
  Blake2sUpdateU64(state, site_id);
  return FinalizeDerivedWord(state, module_id ^ function_id, site_id);
}

inline std::uint64_t DeriveConstantPoolBindingId(std::uint64_t module_id,
                                                 std::uint64_t pool_id) {
  Blake2sState state;
  Blake2sInit(state, kBlake2sOutBytes);
  Blake2sUpdateDomain(state, kDomainConstantBindingV2);
  Blake2sUpdateU64(state, module_id);
  Blake2sUpdateU64(state, pool_id);
  return FinalizeDerivedWord(state, module_id, pool_id);
}

inline std::uint64_t DeriveReferenceCookie(std::span<const std::uint8_t> mac_key,
                                           AuthDescriptorKind descriptor_kind,
                                           std::uint64_t binding_id,
                                           AuthReferenceRole role) {
  Blake2sState state;
  Blake2sInit(state, kBlake2sOutBytes, mac_key);
  Blake2sUpdateDomain(state, kDomainReferenceCookieV2);
  Blake2sUpdateU32(state, static_cast<std::uint32_t>(descriptor_kind));
  Blake2sUpdateU64(state, binding_id);
  Blake2sUpdateU32(state, static_cast<std::uint32_t>(role));
  return FinalizeDerivedWord(state, binding_id, static_cast<std::uint32_t>(role));
}

inline std::uint64_t DeriveBuildKeyCookie(std::span<const std::uint8_t> build_key,
                                          AuthDescriptorKind descriptor_kind,
                                          std::uint64_t binding_id) {
  Blake2sState state;
  Blake2sInit(state, kBlake2sOutBytes, build_key);
  Blake2sUpdateDomain(state, kDomainBuildKeyCookieV2);
  Blake2sUpdateU32(state, static_cast<std::uint32_t>(descriptor_kind));
  Blake2sUpdateU64(state, binding_id);
  Blake2sUpdateU32(state, static_cast<std::uint32_t>(AuthReferenceRole::build_key));
  return FinalizeDerivedWord(state,
                             binding_id,
                             static_cast<std::uint32_t>(AuthReferenceRole::build_key));
}

inline std::array<std::uint64_t, 3> DeriveCacheStatuses(std::span<const std::uint8_t> mac_key,
                                                        AuthDescriptorKind descriptor_kind,
                                                        std::uint64_t binding_id) {
  Blake2sState state;
  Blake2sInit(state, kBlake2sOutBytes, mac_key);
  Blake2sUpdateDomain(state, kDomainCacheStatusV2);
  Blake2sUpdateU32(state, static_cast<std::uint32_t>(descriptor_kind));
  Blake2sUpdateU64(state, binding_id);
  Blake2sUpdateU32(state, 0);

  std::array<std::uint64_t, 3> tokens{};
  tokens[static_cast<std::size_t>(CacheStatusKind::cold)] =
      FinalizeDerivedWord(state, binding_id, static_cast<std::uint32_t>(CacheStatusKind::cold));
  tokens[static_cast<std::size_t>(CacheStatusKind::decoding)] = NormalizeDerivedWord(
      tokens[static_cast<std::size_t>(CacheStatusKind::cold)] ^ 0x6a09e667f3bcc909ULL,
      binding_id,
      static_cast<std::uint32_t>(CacheStatusKind::decoding));
  tokens[static_cast<std::size_t>(CacheStatusKind::decoded)] = NormalizeDerivedWord(
      tokens[static_cast<std::size_t>(CacheStatusKind::cold)] ^ 0xbb67ae8584caa73bULL,
      binding_id,
      static_cast<std::uint32_t>(CacheStatusKind::decoded));

  if (tokens[static_cast<std::size_t>(CacheStatusKind::decoding)] ==
      tokens[static_cast<std::size_t>(CacheStatusKind::cold)]) {
    tokens[static_cast<std::size_t>(CacheStatusKind::decoding)] ^= 0x3c6ef372fe94f82bULL;
    tokens[static_cast<std::size_t>(CacheStatusKind::decoding)] = NormalizeDerivedWord(
        tokens[static_cast<std::size_t>(CacheStatusKind::decoding)],
        binding_id,
        static_cast<std::uint32_t>(CacheStatusKind::decoding));
  }

  if (tokens[static_cast<std::size_t>(CacheStatusKind::decoded)] ==
          tokens[static_cast<std::size_t>(CacheStatusKind::cold)] ||
      tokens[static_cast<std::size_t>(CacheStatusKind::decoded)] ==
          tokens[static_cast<std::size_t>(CacheStatusKind::decoding)]) {
    tokens[static_cast<std::size_t>(CacheStatusKind::decoded)] ^= 0x3c6ef372fe94f82bULL;
    tokens[static_cast<std::size_t>(CacheStatusKind::decoded)] = NormalizeDerivedWord(
        tokens[static_cast<std::size_t>(CacheStatusKind::decoded)],
        binding_id,
        static_cast<std::uint32_t>(CacheStatusKind::decoded));
  }

  return tokens;
}

inline std::uint64_t DeriveCacheStatus(std::span<const std::uint8_t> mac_key,
                                       AuthDescriptorKind descriptor_kind,
                                       std::uint64_t binding_id,
                                       CacheStatusKind status) {
  return DeriveCacheStatuses(mac_key, descriptor_kind, binding_id)[static_cast<std::size_t>(status)];
}

inline Blake2sDigest Prf(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data) {
  return Blake2s(data, key);
}

inline BuildKey DeriveBuildKey(std::uint64_t seed) {
  Blake2sState state;
  Blake2sInit(state, kBlake2sOutBytes);
  Blake2sUpdateDomain(state, kDomainBuild);
  Blake2sUpdateU64(state, seed);
  return Blake2sFinal(state);
}

inline Blake2sDigest DeriveFunctionKey(std::span<const std::uint8_t> build_key,
                                       std::uint64_t module_id,
                                       std::uint64_t function_id) {
  Blake2sState state;
  Blake2sInit(state, kBlake2sOutBytes, build_key);
  Blake2sUpdateDomain(state, kDomainFunction);
  Blake2sUpdateU64(state, module_id);
  Blake2sUpdateU64(state, function_id);
  return Blake2sFinal(state);
}

inline Blake2sDigest DeriveSiteKey(std::span<const std::uint8_t> function_key,
                                   std::span<const std::uint8_t> domain,
                                   std::uint64_t site_id) {
  Blake2sState state;
  Blake2sInit(state, kBlake2sOutBytes, function_key);
  Blake2sUpdateDomain(state, domain);
  Blake2sUpdateU64(state, site_id);
  return Blake2sFinal(state);
}

inline Blake2sDigest DeriveLabeledKey(std::span<const std::uint8_t> key,
                                      std::span<const std::uint8_t> label) {
  Blake2sState state;
  Blake2sInit(state, kBlake2sOutBytes, key);
  Blake2sUpdateDomain(state, label);
  return Blake2sFinal(state);
}

inline StringNonce DeriveStringNonce(std::span<const std::uint8_t> site_key) {
  const Blake2sDigest digest = DeriveLabeledKey(site_key, kDomainNonce);
  StringNonce nonce{};
  std::memcpy(nonce.data(), digest.data(), nonce.size());
  return nonce;
}

inline Blake2sDigest MakeStringKeystreamBlock(std::span<const std::uint8_t> enc_key,
                                              const StringNonce& nonce,
                                              std::uint64_t counter) {
  Blake2sState state;
  Blake2sInit(state, kBlake2sOutBytes, enc_key);
  Blake2sUpdateDomain(state, kDomainStream);
  Blake2sUpdate(state, nonce);
  Blake2sUpdateU64(state, counter);
  return Blake2sFinal(state);
}

inline void XorStringPayload(std::span<std::uint8_t> output,
                             std::span<const std::uint8_t> input,
                             std::span<const std::uint8_t> enc_key,
                             const StringNonce& nonce) {
  std::size_t offset = 0;
  std::uint64_t counter = 0;
  while (offset < input.size()) {
    const Blake2sDigest block = MakeStringKeystreamBlock(enc_key, nonce, counter++);
    const std::size_t block_size = std::min<std::size_t>(block.size(), input.size() - offset);
    for (std::size_t index = 0; index < block_size; ++index) {
      output[offset + index] = static_cast<std::uint8_t>(input[offset + index] ^ block[index]);
    }
    offset += block_size;
  }
}

inline StringTag ComputeStringTag(std::span<const std::uint8_t> mac_key,
                                  const StringAuthMetadata& metadata,
                                  std::span<const std::uint8_t> ciphertext) {
  Blake2sState state;
  Blake2sInit(state, kBlake2sOutBytes, mac_key);
  Blake2sUpdateDomain(state, kDomainStringTag);
  Blake2sUpdateU32(state, metadata.version);
  Blake2sUpdateU32(state, metadata.flags);
  Blake2sUpdateU64(state, metadata.length);
  Blake2sUpdateU64(state, metadata.module_id);
  Blake2sUpdateU64(state, metadata.function_id);
  Blake2sUpdateU64(state, metadata.site_id);
  Blake2sUpdateU64(state, metadata.binding_id);
  Blake2sUpdateU64(state, metadata.destination_cookie);
  Blake2sUpdateU64(state, metadata.ciphertext_cookie);
  Blake2sUpdateU64(state, metadata.build_key_cookie);
  Blake2sUpdateU64(state, metadata.state_cookie);
  Blake2sUpdate(state, metadata.nonce);
  Blake2sUpdate(state, ciphertext);
  const Blake2sDigest digest = Blake2sFinal(state);

  StringTag tag{};
  std::memcpy(tag.data(), digest.data(), tag.size());
  return tag;
}

inline StringTag ComputeConstantPoolTag(std::span<const std::uint8_t> mac_key,
                                        const ConstantPoolAuthMetadata& metadata,
                                        std::span<const std::uint8_t> ciphertext) {
  Blake2sState state;
  Blake2sInit(state, kBlake2sOutBytes, mac_key);
  Blake2sUpdateDomain(state, kDomainConstantPoolTag);
  Blake2sUpdateU32(state, metadata.version);
  Blake2sUpdateU32(state, metadata.flags);
  Blake2sUpdateU64(state, metadata.length);
  Blake2sUpdateU64(state, metadata.module_id);
  Blake2sUpdateU64(state, metadata.pool_id);
  Blake2sUpdateU64(state, metadata.binding_id);
  Blake2sUpdateU64(state, metadata.destination_cookie);
  Blake2sUpdateU64(state, metadata.ciphertext_cookie);
  Blake2sUpdateU64(state, metadata.build_key_cookie);
  Blake2sUpdateU64(state, metadata.state_cookie);
  Blake2sUpdate(state, metadata.nonce);
  Blake2sUpdate(state, ciphertext);
  const Blake2sDigest digest = Blake2sFinal(state);

  StringTag tag{};
  std::memcpy(tag.data(), digest.data(), tag.size());
  return tag;
}

inline bool ConstantTimeEqual(std::span<const std::uint8_t> lhs, std::span<const std::uint8_t> rhs) {
  if (lhs.size() != rhs.size()) { return false; }

  std::uint8_t diff = 0;
  for (std::size_t index = 0; index < lhs.size(); ++index) {
    diff |= static_cast<std::uint8_t>(lhs[index] ^ rhs[index]);
  }
  return diff == 0;
}

inline std::uint64_t LoadWordPair(const std::array<std::uint8_t, 16>& value, unsigned word_index) {
  return Load64(value.data() + (word_index * 8));
}

inline StringNonce MakeNonce(std::uint64_t low, std::uint64_t high) {
  StringNonce nonce{};
  Store64(low, nonce.data());
  Store64(high, nonce.data() + 8);
  return nonce;
}

inline StringTag MakeTag(std::uint64_t low, std::uint64_t high) {
  StringTag tag{};
  Store64(low, tag.data());
  Store64(high, tag.data() + 8);
  return tag;
}

}  // namespace obf::auth
