#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#include "obf/support/runtime_atomic.h"

#if !defined(_WIN32) && !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

/*
 * Native 32-bit MSVC may retain a compare-exchange fallback for tear-free U64
 * loads. That fallback performs a write, so only the protected-page U64
 * assertions are skipped there.
 */
#if defined(_MSC_VER) && !defined(__clang__) && defined(_M_IX86)
#define OBF_SKIP_READONLY_U64_LOAD_TESTS 1
#else
#define OBF_SKIP_READONLY_U64_LOAD_TESTS 0
#endif

struct AtomicTestPage {
  uint64_t u64_value;
  uint32_t u32_value;
  uint32_t padding;
};

struct TestPage {
  void* base;
  size_t size;
  struct AtomicTestPage* values;
};

static const uint64_t kInitialU64Value = UINT64_C(0x1122334455667788);
static const uint32_t kInitialU32Value = UINT32_C(0xa5c31d72);
static const uint64_t kStoreRelaxedU64Value = UINT64_C(0x8877665544332211);
static const uint64_t kStoreReleaseU64Value = UINT64_C(0x0f1e2d3c4b5a6978);
static const uint32_t kStoreReleaseU32Value = UINT32_C(0x13579bdf);
static const uint64_t kCasAcquireDesiredValue = UINT64_C(0x55aa55aa11224488);
static const uint64_t kCasAcquireFailExpectedValue = UINT64_C(0x0001020304050607);
static const uint64_t kCasAcquireFailDesiredValue = UINT64_C(0xdeadbeefcafef00d);
static const uint64_t kCasAcqRelDesiredValue = UINT64_C(0x7f6e5d4c3b2a1908);
static const uint64_t kCasAcqRelFailExpectedValue = UINT64_C(0x1021324354657687);
static const uint64_t kCasAcqRelFailDesiredValue = UINT64_C(0x0101010101010101);
static const uint64_t kReadOnlyU64Value = UINT64_C(0xfedcba9876543210);
static const uint32_t kReadOnlyU32Value = UINT32_C(0x2468ace1);

static int g_failures = 0;

static void Fail(const char* message) {
  ++g_failures;
  fprintf(stderr, "[fail] %s\n", message);
}

static void ExpectTrue(int condition, const char* message) {
  if (!condition) { Fail(message); }
}

static void ExpectU64Eq(uint64_t actual, uint64_t expected, const char* message) {
  if (actual != expected) { Fail(message); }
}

static void ExpectU32Eq(uint32_t actual, uint32_t expected, const char* message) {
  if (actual != expected) { Fail(message); }
}

static void FreeTestPage(struct TestPage* page) {
  if (page->base == NULL) { return; }

#if defined(_WIN32)
  (void)VirtualFree(page->base, 0, MEM_RELEASE);
#else
  (void)munmap(page->base, page->size);
#endif

  page->base = NULL;
  page->size = 0;
  page->values = NULL;
}

static int AllocateTestPage(struct TestPage* page) {
  memset(page, 0, sizeof(*page));

#if defined(_WIN32)
  SYSTEM_INFO system_info;

  GetSystemInfo(&system_info);
  page->size = (size_t)system_info.dwPageSize;
  if (page->size == 0) {
    Fail("page size discovery must succeed");
    return 0;
  }

  page->base = VirtualAlloc(NULL, page->size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (page->base == NULL) {
    Fail("page allocation must succeed");
    return 0;
  }
#else
  const long page_size = sysconf(_SC_PAGESIZE);

  if (page_size <= 0) {
    Fail("page size discovery must succeed");
    return 0;
  }

  page->size = (size_t)page_size;
  page->base = mmap(NULL, page->size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page->base == MAP_FAILED) {
    page->base = NULL;
    Fail("page allocation must succeed");
    return 0;
  }
#endif

  if (((uintptr_t)page->base % page->size) != 0) {
    Fail("page allocation must be page aligned");
    FreeTestPage(page);
    return 0;
  }

  if (page->size < sizeof(*page->values)) {
    Fail("test page must fit the atomic fixture values");
    FreeTestPage(page);
    return 0;
  }

  memset(page->base, 0, page->size);
  page->values = (struct AtomicTestPage*)page->base;
  return 1;
}

static int ProtectTestPageReadOnly(struct TestPage* page) {
#if defined(_WIN32)
  DWORD old_protect = 0;

  if (!VirtualProtect(page->base, page->size, PAGE_READONLY, &old_protect)) {
    Fail("making the atomic test page read-only must succeed");
    return 0;
  }
#else
  if (mprotect(page->base, page->size, PROT_READ) != 0) {
    Fail("making the atomic test page read-only must succeed");
    return 0;
  }
#endif

  return 1;
}

static void TestWritableOperations(void) {
  struct TestPage page;
  uint64_t expected_u64;
  int exchanged;

  if (!AllocateTestPage(&page)) { return; }

  page.values->u64_value = kInitialU64Value;
  page.values->u32_value = kInitialU32Value;

  ExpectU64Eq(ObfAtomicLoadU64Relaxed(&page.values->u64_value),
              kInitialU64Value,
              "writable U64 relaxed load must read the seeded value");
  ExpectU64Eq(ObfAtomicLoadU64Acquire(&page.values->u64_value),
              kInitialU64Value,
              "writable U64 acquire load must read the seeded value");
  ExpectU32Eq(ObfAtomicLoadU32Acquire(&page.values->u32_value),
              kInitialU32Value,
              "writable U32 acquire load must read the seeded value");

  ObfAtomicStoreU64Relaxed(&page.values->u64_value, kStoreRelaxedU64Value);
  ExpectU64Eq(page.values->u64_value,
              kStoreRelaxedU64Value,
              "U64 relaxed store must update writable state");

  ObfAtomicStoreU64Release(&page.values->u64_value, kStoreReleaseU64Value);
  ExpectU64Eq(page.values->u64_value,
              kStoreReleaseU64Value,
              "U64 release store must update writable state");

  ObfAtomicStoreU32Release(&page.values->u32_value, kStoreReleaseU32Value);
  ExpectU32Eq(page.values->u32_value,
              kStoreReleaseU32Value,
              "U32 release store must update writable state");

  expected_u64 = kStoreReleaseU64Value;
  exchanged = ObfAtomicCompareExchangeU64AcquireRelaxed(
      &page.values->u64_value, &expected_u64, kCasAcquireDesiredValue);
  ExpectTrue(exchanged == 1,
             "U64 acquire-relaxed compare-exchange must succeed when expected matches");
  ExpectU64Eq(page.values->u64_value,
              kCasAcquireDesiredValue,
              "successful U64 acquire-relaxed compare-exchange must store the desired value");
  ExpectU64Eq(expected_u64,
              kStoreReleaseU64Value,
              "successful U64 acquire-relaxed compare-exchange must keep expected unchanged");

  expected_u64 = kCasAcquireFailExpectedValue;
  exchanged = ObfAtomicCompareExchangeU64AcquireRelaxed(
      &page.values->u64_value, &expected_u64, kCasAcquireFailDesiredValue);
  ExpectTrue(exchanged == 0,
             "U64 acquire-relaxed compare-exchange must fail when expected mismatches");
  ExpectU64Eq(page.values->u64_value,
              kCasAcquireDesiredValue,
              "failed U64 acquire-relaxed compare-exchange must not change the value");
  ExpectU64Eq(expected_u64,
              kCasAcquireDesiredValue,
              "failed U64 acquire-relaxed compare-exchange must report the observed value");

  expected_u64 = kCasAcquireDesiredValue;
  exchanged = ObfAtomicCompareExchangeU64AcqRelRelaxed(
      &page.values->u64_value, &expected_u64, kCasAcqRelDesiredValue);
  ExpectTrue(exchanged == 1,
             "U64 acqrel-relaxed compare-exchange must succeed when expected matches");
  ExpectU64Eq(page.values->u64_value,
              kCasAcqRelDesiredValue,
              "successful U64 acqrel-relaxed compare-exchange must store the desired value");
  ExpectU64Eq(expected_u64,
              kCasAcquireDesiredValue,
              "successful U64 acqrel-relaxed compare-exchange must keep expected unchanged");

  expected_u64 = kCasAcqRelFailExpectedValue;
  exchanged = ObfAtomicCompareExchangeU64AcqRelRelaxed(
      &page.values->u64_value, &expected_u64, kCasAcqRelFailDesiredValue);
  ExpectTrue(exchanged == 0,
             "U64 acqrel-relaxed compare-exchange must fail when expected mismatches");
  ExpectU64Eq(page.values->u64_value,
              kCasAcqRelDesiredValue,
              "failed U64 acqrel-relaxed compare-exchange must not change the value");
  ExpectU64Eq(expected_u64,
              kCasAcqRelDesiredValue,
              "failed U64 acqrel-relaxed compare-exchange must report the observed value");

  FreeTestPage(&page);
}

/* A read-modify-write load will fault here once the page is made read-only. */
static void TestReadOnlyLoads(void) {
  struct TestPage page;

  if (!AllocateTestPage(&page)) { return; }

  page.values->u64_value = kReadOnlyU64Value;
  page.values->u32_value = kReadOnlyU32Value;

  if (!ProtectTestPageReadOnly(&page)) {
    FreeTestPage(&page);
    return;
  }

#if OBF_SKIP_READONLY_U64_LOAD_TESTS
  fprintf(stdout, "[skip] native 32-bit MSVC may retain a CAS fallback for tear-free U64 loads\n");
#else
  ExpectU64Eq(ObfAtomicLoadU64Relaxed(&page.values->u64_value),
              kReadOnlyU64Value,
              "U64 relaxed load must read a read-only page without faulting");
  ExpectU64Eq(ObfAtomicLoadU64Acquire(&page.values->u64_value),
              kReadOnlyU64Value,
              "U64 acquire load must read a read-only page without faulting");
#endif

  ExpectU32Eq(ObfAtomicLoadU32Acquire(&page.values->u32_value),
              kReadOnlyU32Value,
              "U32 acquire load must read a read-only page without faulting");

  FreeTestPage(&page);
}

int main(void) {
  TestWritableOperations();
  TestReadOnlyLoads();

  if (g_failures != 0) { return EXIT_FAILURE; }

  return EXIT_SUCCESS;
}
