#include <stdint.h>

#if defined(_MSC_VER)
#include <intrin.h>
#pragma section(".CRT$XCU", read)
#elif defined(__i386__) || defined(__x86_64__)
#include <immintrin.h>
#endif

#if !defined(_MSC_VER) && (defined(__i386__) || defined(__x86_64__))
#include <x86intrin.h>
#endif

#if !defined(__i386__) && !defined(__x86_64__) && !defined(_M_IX86) && !defined(_M_X64)
#include <time.h>
#endif

uint64_t __obf_entropy_anchor = 0;
uint64_t * __obf_entropy_anchor_ref = &__obf_entropy_anchor;

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
  __builtin_cpu_init();
  return __builtin_cpu_supports("rdrnd");
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
