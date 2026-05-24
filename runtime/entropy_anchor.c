#include <stdint.h>

#include "obf/support/runtime_abi_generated.h"

#if defined(_MSC_VER)
#include <intrin.h>
#pragma section(".CRT$XCU", read)
#elif defined(__i386__) || defined(__x86_64__)
#include <immintrin.h>
#endif

#if !defined(_MSC_VER) && (defined(__i386__) || defined(__x86_64__))
#include <x86intrin.h>
#include <cpuid.h>
#endif

#if !defined(__i386__) && !defined(__x86_64__) && !defined(_M_IX86) && !defined(_M_X64)
#include <time.h>
#endif

uint64_t OBF_RT_ENTROPY_ANCHOR = 0;
static uint64_t * const kEntropyAnchorRef = &OBF_RT_ENTROPY_ANCHOR;

struct ObfEntropyPair {
  uint64_t direct;
  uint64_t indirect;
};

static struct ObfEntropyPair BuildEntropyPair(uint64_t direct, uint64_t indirect) {
  const struct ObfEntropyPair pair = {direct, indirect};
  return pair;
}

#if defined(_MSC_VER)
__declspec(noinline)
#else
__attribute__((noinline))
#endif
struct ObfEntropyPair OBF_RT_LOAD_ENTROPY_PAIR(void) {
  const uint64_t direct = OBF_RT_ENTROPY_ANCHOR;
  uint64_t * const ref_ptr = kEntropyAnchorRef;
  *ref_ptr = direct;
  const uint64_t indirect = OBF_RT_ENTROPY_ANCHOR;
  return BuildEntropyPair(direct, indirect);
}

#if defined(_MSC_VER)
__declspec(noinline)
#else
__attribute__((noinline))
#endif
struct ObfEntropyPair OBF_RT_LOAD_ENTROPY_PAIR_V1(void) {
  const uint64_t direct = OBF_RT_ENTROPY_ANCHOR;
  uint64_t * const ref_ptr = kEntropyAnchorRef;
  volatile uint64_t scratch_direct = direct;
  volatile uint64_t scratch_indirect = 0;
  *ref_ptr = scratch_direct;
  scratch_indirect = *ref_ptr;
  return BuildEntropyPair((uint64_t)scratch_direct, (uint64_t)scratch_indirect);
}

#if defined(_MSC_VER)
__declspec(noinline)
#else
__attribute__((noinline))
#endif
struct ObfEntropyPair OBF_RT_LOAD_ENTROPY_PAIR_V2(void) {
  const uint64_t base = OBF_RT_ENTROPY_ANCHOR;
  uint64_t * const ref_ptr = kEntropyAnchorRef;
  const uint64_t low = base & 0xffffffffULL;
  const uint64_t high = (base >> 32) & 0xffffffffULL;
  const uint64_t direct = low | (high << 32);
  *ref_ptr = direct;
  const uint64_t indirect_source = *ref_ptr;
  const uint64_t indirect_low = indirect_source & 0xffffffffULL;
  const uint64_t indirect_high = (indirect_source >> 32) & 0xffffffffULL;
  const uint64_t indirect = indirect_low | (indirect_high << 32);
  return BuildEntropyPair(direct, indirect);
}

#if defined(_MSC_VER)
__declspec(noinline)
#else
__attribute__((noinline))
#endif
struct ObfEntropyPair OBF_RT_LOAD_ENTROPY_PAIR_V3(void) {
  const uint64_t base = OBF_RT_ENTROPY_ANCHOR;
  uint64_t * const ref_ptr = kEntropyAnchorRef;
  volatile uint64_t key = 0x9e3779b97f4a7c15ULL;
  const uint64_t direct_masked = base ^ key;
  const uint64_t direct = direct_masked ^ key;
  *ref_ptr = direct;
  const uint64_t indirect_masked = (*ref_ptr) ^ key;
  const uint64_t indirect = indirect_masked ^ key;
  return BuildEntropyPair(direct, indirect);
}

#if defined(_MSC_VER)
__declspec(noinline)
#else
__attribute__((noinline))
#endif
struct ObfEntropyPair OBF_RT_LOAD_ENTROPY_PAIR_V4(void) {
  const uint64_t base = OBF_RT_ENTROPY_ANCHOR;
  uint64_t * const ref_ptr = kEntropyAnchorRef;
  volatile uint64_t bias = 0x6a09e667f3bcc909ULL;
  const uint64_t direct_biased = base + bias;
  const uint64_t direct = direct_biased - bias;
  *ref_ptr = direct;
  const uint64_t indirect_biased = (*ref_ptr) + bias;
  const uint64_t indirect = indirect_biased - bias;
  return BuildEntropyPair(direct, indirect);
}

static uint64_t ReadTimestampEntropy(void) {
#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
  return (uint64_t)__rdtsc();
#else
  struct timespec now;
  timespec_get(&now, TIME_UTC);
  return ((uint64_t)now.tv_sec << 32) ^ (uint64_t)now.tv_nsec;
#endif
}

static int CpuSupportsRdrand(void) {
#if defined(_MSC_VER) && defined(_M_X64)
  int cpu_info[4] = {0, 0, 0, 0};
  __cpuid(cpu_info, 1);
  return (cpu_info[2] & (1 << 30)) != 0;
#elif defined(__x86_64__) && (defined(__clang__) || defined(__GNUC__))
  unsigned int eax = 0;
  unsigned int ebx = 0;
  unsigned int ecx = 0;
  unsigned int edx = 0;
  if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) == 0) {
    return 0;
  }
  return (ecx & (1u << 30)) != 0;
#else
  return 0;
#endif
}

#if defined(_MSC_VER) && defined(_M_X64)
static int TryReadRdrand(uint64_t *entropy_bits) {
  unsigned __int64 value = 0;
  const int success = _rdrand64_step(&value);
  if (success != 0) {
    *entropy_bits = (uint64_t)value;
  }
  return success;
}
#elif defined(__x86_64__) && (defined(__clang__) || defined(__GNUC__))
__attribute__((target("rdrnd"))) static int TryReadRdrand(uint64_t *entropy_bits) {
  unsigned long long value = 0;
  const int success = _rdrand64_step(&value);
  if (success != 0) {
    *entropy_bits = (uint64_t)value;
  }
  return success;
}
#else
static int TryReadRdrand(uint64_t *entropy_bits) {
  (void)entropy_bits;
  return 0;
}
#endif

static uint64_t ReadHardwareEntropy(void) {
  uint64_t entropy_bits = 0;

  if (CpuSupportsRdrand()) {
    for (int attempt = 0; attempt < 10; ++attempt) {
      if (TryReadRdrand(&entropy_bits) != 0) {
        return entropy_bits;
      }
    }
  }

  return ReadTimestampEntropy();
}

static void InitializeObfEntropyAnchor(void) {
  OBF_RT_ENTROPY_ANCHOR ^= ReadHardwareEntropy();
}

#if defined(_MSC_VER)
__declspec(allocate(".CRT$XCU")) void (*const kObfEntropyCtor)(void) =
    InitializeObfEntropyAnchor;
#else
__attribute__((constructor)) static void ObfEntropyCtor(void) {
  InitializeObfEntropyAnchor();
}
#endif
