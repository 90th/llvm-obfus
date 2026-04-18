#include <stdint.h>

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

uint64_t __obf_entropy_anchor = 0;
uint64_t * __obf_entropy_anchor_ref = &__obf_entropy_anchor;

struct ObfEntropyPair {
  uint64_t direct;
  uint64_t indirect;
};

#if defined(_MSC_VER)
__declspec(noinline)
#else
__attribute__((noinline))
#endif
struct ObfEntropyPair __obf_load_entropy_pair(void) {
  const uint64_t direct = __obf_entropy_anchor;
  uint64_t * const ref_ptr = __obf_entropy_anchor_ref;
  *ref_ptr = direct;
  const uint64_t indirect = __obf_entropy_anchor;
  const struct ObfEntropyPair pair = {direct, indirect};
  return pair;
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
  __obf_entropy_anchor ^= ReadHardwareEntropy();
}

#if defined(_MSC_VER)
__declspec(allocate(".CRT$XCU")) void (*const kObfEntropyCtor)(void) =
    InitializeObfEntropyAnchor;
#else
__attribute__((constructor)) static void ObfEntropyCtor(void) {
  InitializeObfEntropyAnchor();
}
#endif
