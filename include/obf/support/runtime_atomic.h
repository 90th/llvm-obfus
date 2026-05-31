#pragma once

#include <stdint.h>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

static inline uint64_t ObfAtomicLoadU64Relaxed(const uint64_t* value) {
#if defined(_MSC_VER)
  return (uint64_t)_InterlockedCompareExchange64((volatile __int64*)value, 0, 0);
#else
  return __atomic_load_n(value, __ATOMIC_RELAXED);
#endif
}

static inline void ObfAtomicStoreU64Relaxed(uint64_t* value, uint64_t next) {
#if defined(_MSC_VER)
  (void)_InterlockedExchange64((volatile __int64*)value, (__int64)next);
#else
  __atomic_store_n(value, next, __ATOMIC_RELAXED);
#endif
}

static inline uint32_t ObfAtomicLoadU32Acquire(const uint32_t* value) {
#if defined(_MSC_VER)
  return (uint32_t)_InterlockedCompareExchange((volatile long*)value, 0, 0);
#else
  return __atomic_load_n(value, __ATOMIC_ACQUIRE);
#endif
}

static inline void ObfAtomicStoreU32Release(uint32_t* value, uint32_t next) {
#if defined(_MSC_VER)
  (void)_InterlockedExchange((volatile long*)value, (long)next);
#else
  __atomic_store_n(value, next, __ATOMIC_RELEASE);
#endif
}

static inline int ObfAtomicCompareExchangeU32AcquireRelaxed(uint32_t* value,
                                                            uint32_t* expected,
                                                            uint32_t desired) {
#if defined(_MSC_VER)
  const long observed = _InterlockedCompareExchange(
      (volatile long*)value, (long)desired, (long)(*expected));
  if ((uint32_t)observed == *expected) {
    return 1;
  }
  *expected = (uint32_t)observed;
  return 0;
#else
  return __atomic_compare_exchange_n(
      value, expected, desired, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
#endif
}