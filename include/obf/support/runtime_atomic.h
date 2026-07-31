#pragma once

#include <stdint.h>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

static inline uint64_t ObfAtomicLoadU64Relaxed(const uint64_t* value) {
#if defined(__clang__) || defined(__GNUC__)
  return __atomic_load_n(value, __ATOMIC_RELAXED);
#elif defined(_MSC_VER)
#if defined(_M_IX86)
  /* 32-bit x86 fallback: no pure tear-free 64-bit load intrinsic. */
  return (uint64_t)_InterlockedCompareExchange64((volatile __int64*)value, 0, 0);
#elif defined(_M_ARM)
  return (uint64_t)__ldrexd((const volatile __int64*)value);
#else
  return (uint64_t)__iso_volatile_load64((const volatile __int64*)value);
#endif
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

static inline uint64_t ObfAtomicLoadU64Acquire(const uint64_t* value) {
#if defined(__clang__) || defined(__GNUC__)
  return __atomic_load_n(value, __ATOMIC_ACQUIRE);
#elif defined(_MSC_VER)
#if defined(_M_ARM64) || defined(_M_ARM64EC)
  return (uint64_t)__load_acquire64((const volatile unsigned __int64*)value);
#elif defined(_M_ARM)
  const uint64_t observed = (uint64_t)__ldrexd((const volatile __int64*)value);
  __dmb(_ARM_BARRIER_ISH);
  return observed;
#elif defined(_M_IX86)
  /* 32-bit x86 fallback: no pure tear-free 64-bit load intrinsic. */
  return (uint64_t)_InterlockedCompareExchange64((volatile __int64*)value, 0, 0);
#else
  return (uint64_t)__iso_volatile_load64((const volatile __int64*)value);
#endif
#else
  return __atomic_load_n(value, __ATOMIC_ACQUIRE);
#endif
}

static inline void ObfAtomicStoreU64Release(uint64_t* value, uint64_t next) {
#if defined(_MSC_VER)
  (void)_InterlockedExchange64((volatile __int64*)value, (__int64)next);
#else
  __atomic_store_n(value, next, __ATOMIC_RELEASE);
#endif
}

static inline uint32_t ObfAtomicLoadU32Acquire(const uint32_t* value) {
#if defined(__clang__) || defined(__GNUC__)
  return __atomic_load_n(value, __ATOMIC_ACQUIRE);
#elif defined(_MSC_VER)
#if defined(_M_ARM64) || defined(_M_ARM64EC)
  return (uint32_t)__load_acquire32((const volatile unsigned __int32*)value);
#elif defined(_M_ARM)
  const uint32_t observed =
      (uint32_t)__iso_volatile_load32((const volatile __int32*)value);
  __dmb(_ARM_BARRIER_ISH);
  return observed;
#else
  return (uint32_t)__iso_volatile_load32((const volatile __int32*)value);
#endif
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

static inline int ObfAtomicCompareExchangeU64AcquireRelaxed(uint64_t* value,
                                                            uint64_t* expected,
                                                            uint64_t desired) {
#if defined(_MSC_VER)
  const __int64 observed = _InterlockedCompareExchange64(
      (volatile __int64*)value, (__int64)desired, (__int64)(*expected));
  if ((uint64_t)observed == *expected) {
    return 1;
  }
  *expected = (uint64_t)observed;
  return 0;
#else
  return __atomic_compare_exchange_n(
      value, expected, desired, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
#endif
}
static inline int ObfAtomicCompareExchangeU64AcqRelRelaxed(uint64_t* value,
                                                           uint64_t* expected,
                                                           uint64_t desired) {
#if defined(_MSC_VER)
  const __int64 observed = _InterlockedCompareExchange64(
      (volatile __int64*)value, (__int64)desired, (__int64)(*expected));
  if ((uint64_t)observed == *expected) {
    return 1;
  }
  *expected = (uint64_t)observed;
  return 0;
#else
  return __atomic_compare_exchange_n(
      value, expected, desired, 0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED);
#endif
}
