#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <pthread.h>
#endif

#define ObfAtomicLoadU64Acquire ObfAtomicLoadU64AcquireBase
#define ObfAtomicCompareExchangeU64AcqRelRelaxed ObfAtomicCompareExchangeU64AcqRelRelaxedBase
#include "obf/support/runtime_atomic.h"
#undef ObfAtomicLoadU64Acquire
#undef ObfAtomicCompareExchangeU64AcqRelRelaxed

#if defined(_MSC_VER)
#define TEST_THREAD_LOCAL __declspec(thread)
#else
#define TEST_THREAD_LOCAL __thread
#endif

static int g_failures = 0;

static void Fail(const char* message) {
  ++g_failures;
  fprintf(stderr, "[fail] %s\n", message);
}

static void ExpectPtrEq(const void* actual, const void* expected, const char* message) {
  if (actual != expected) { Fail(message); }
}

static void ExpectU64Eq(uint64_t actual, uint64_t expected, const char* message) {
  if (actual != expected) { Fail(message); }
}

static void
ExpectBufferEq(const uint8_t* actual, const uint8_t* expected, size_t size, const char* message) {
  if (memcmp(actual, expected, size) != 0) { Fail(message); }
}

#if defined(_WIN32)
struct TestMutex {
  CRITICAL_SECTION handle;
};

struct TestCond {
  CONDITION_VARIABLE handle;
};

static void TestMutexInit(struct TestMutex* mutex) { InitializeCriticalSection(&mutex->handle); }

static void TestMutexDestroy(struct TestMutex* mutex) { DeleteCriticalSection(&mutex->handle); }

static void TestMutexLock(struct TestMutex* mutex) { EnterCriticalSection(&mutex->handle); }

static void TestMutexUnlock(struct TestMutex* mutex) { LeaveCriticalSection(&mutex->handle); }

static void TestCondInit(struct TestCond* cond) { InitializeConditionVariable(&cond->handle); }

static void TestCondDestroy(struct TestCond* cond) { (void)cond; }

static void TestCondWait(struct TestCond* cond, struct TestMutex* mutex) {
  SleepConditionVariableCS(&cond->handle, &mutex->handle, INFINITE);
}

static void TestCondBroadcast(struct TestCond* cond) { WakeAllConditionVariable(&cond->handle); }

static void SleepMillis(unsigned milliseconds) { Sleep(milliseconds); }

typedef HANDLE TestThread;
typedef DWORD(WINAPI* TestThreadProc)(void*);
#define TEST_THREAD_PROC(name) static DWORD WINAPI name(void* raw)

static int
StartThread(TestThread* thread, TestThreadProc proc, void* argument, const char* message) {
  *thread = CreateThread(NULL, 0, proc, argument, 0, NULL);
  if (*thread != NULL) { return 1; }
  Fail(message);
  return 0;
}

static void JoinThread(TestThread* thread, const char* message) {
  if (*thread == NULL) { return; }
  if (WaitForSingleObject(*thread, INFINITE) != WAIT_OBJECT_0) { Fail(message); }
  CloseHandle(*thread);
  *thread = NULL;
}
#else
struct TestMutex {
  pthread_mutex_t handle;
};

struct TestCond {
  pthread_cond_t handle;
};

static void TestMutexInit(struct TestMutex* mutex) {
  if (pthread_mutex_init(&mutex->handle, NULL) != 0) { abort(); }
}

static void TestMutexDestroy(struct TestMutex* mutex) {
  (void)pthread_mutex_destroy(&mutex->handle);
}

static void TestMutexLock(struct TestMutex* mutex) { (void)pthread_mutex_lock(&mutex->handle); }

static void TestMutexUnlock(struct TestMutex* mutex) { (void)pthread_mutex_unlock(&mutex->handle); }

static void TestCondInit(struct TestCond* cond) {
  if (pthread_cond_init(&cond->handle, NULL) != 0) { abort(); }
}

static void TestCondDestroy(struct TestCond* cond) { (void)pthread_cond_destroy(&cond->handle); }

static void TestCondWait(struct TestCond* cond, struct TestMutex* mutex) {
  (void)pthread_cond_wait(&cond->handle, &mutex->handle);
}

static void TestCondBroadcast(struct TestCond* cond) {
  (void)pthread_cond_broadcast(&cond->handle);
}

static void SleepMillis(unsigned milliseconds) {
  const struct timespec delay = {
      .tv_sec = (time_t)(milliseconds / 1000u),
      .tv_nsec = (long)(milliseconds % 1000u) * 1000000L,
  };
  (void)nanosleep(&delay, NULL);
}

typedef pthread_t TestThread;
typedef void* (*TestThreadProc)(void*);
#define TEST_THREAD_PROC(name) static void* name(void* raw)

static int
StartThread(TestThread* thread, TestThreadProc proc, void* argument, const char* message) {
  if (pthread_create(thread, NULL, proc, argument) == 0) { return 1; }
  Fail(message);
  return 0;
}

static void JoinThread(TestThread* thread, const char* message) {
  if (pthread_join(*thread, NULL) != 0) { Fail(message); }
  (void)message;
}
#endif

struct TestStartGate {
  struct TestMutex mutex;
  struct TestCond cond;
  unsigned ready;
  int released;
};

static void TestStartGateInit(struct TestStartGate* gate) {
  TestMutexInit(&gate->mutex);
  TestCondInit(&gate->cond);
  gate->ready = 0;
  gate->released = 0;
}

static void TestStartGateDestroy(struct TestStartGate* gate) {
  TestCondDestroy(&gate->cond);
  TestMutexDestroy(&gate->mutex);
}

static void TestStartGateWait(struct TestStartGate* gate) {
  TestMutexLock(&gate->mutex);
  ++gate->ready;
  TestCondBroadcast(&gate->cond);
  while (!gate->released) { TestCondWait(&gate->cond, &gate->mutex); }
  TestMutexUnlock(&gate->mutex);
}

static void TestStartGateRelease(struct TestStartGate* gate) {
  TestMutexLock(&gate->mutex);
  gate->released = 1;
  TestCondBroadcast(&gate->cond);
  TestMutexUnlock(&gate->mutex);
}

static int
WaitForStartGateReady(struct TestStartGate* gate, unsigned expected_ready, const char* message) {
  for (unsigned attempt = 0; attempt < 5000u; ++attempt) {
    unsigned ready;

    TestMutexLock(&gate->mutex);
    ready = gate->ready;
    TestMutexUnlock(&gate->mutex);
    if (ready == expected_ready) { return 1; }
    SleepMillis(1u);
  }
  Fail(message);
  return 0;
}

enum ThreadRole {
  kThreadRoleNone = 0,
  kThreadRoleWriter = 1,
  kThreadRoleReader = 2,
};

TEST_THREAD_LOCAL enum ThreadRole g_thread_role = kThreadRoleNone;

struct AtomicHookState {
  int enabled;
  const uint64_t* status_address;
  uint64_t* completion_address;
  uint64_t cold_status;
  int writer_blocked;
  int writer_may_resume;
  int reader_blocked;
  int reader_may_resume;
  struct TestMutex mutex;
  struct TestCond cond;
};

static struct AtomicHookState g_atomic_hook;

static void InitializeAtomicHook(void) {
  memset(&g_atomic_hook, 0, sizeof(g_atomic_hook));
  TestMutexInit(&g_atomic_hook.mutex);
  TestCondInit(&g_atomic_hook.cond);
}

static void DestroyAtomicHook(void) {
  TestCondDestroy(&g_atomic_hook.cond);
  TestMutexDestroy(&g_atomic_hook.mutex);
}

static void ConfigureAtomicHook(const uint64_t* status_address,
                                uint64_t* completion_address,
                                uint64_t cold_status) {
  TestMutexLock(&g_atomic_hook.mutex);
  g_atomic_hook.enabled = 1;
  g_atomic_hook.status_address = status_address;
  g_atomic_hook.completion_address = completion_address;
  g_atomic_hook.cold_status = cold_status;
  g_atomic_hook.writer_blocked = 0;
  g_atomic_hook.writer_may_resume = 0;
  g_atomic_hook.reader_blocked = 0;
  g_atomic_hook.reader_may_resume = 0;
  TestMutexUnlock(&g_atomic_hook.mutex);
}

static void ReleaseAtomicHookWaiters(void) {
  TestMutexLock(&g_atomic_hook.mutex);
  g_atomic_hook.writer_may_resume = 1;
  g_atomic_hook.reader_may_resume = 1;
  TestCondBroadcast(&g_atomic_hook.cond);
  TestMutexUnlock(&g_atomic_hook.mutex);
}

static void DisableAtomicHook(void) {
  ReleaseAtomicHookWaiters();
  TestMutexLock(&g_atomic_hook.mutex);
  g_atomic_hook.enabled = 0;
  g_atomic_hook.status_address = NULL;
  g_atomic_hook.completion_address = NULL;
  g_atomic_hook.cold_status = 0;
  g_atomic_hook.writer_blocked = 0;
  g_atomic_hook.writer_may_resume = 0;
  g_atomic_hook.reader_blocked = 0;
  g_atomic_hook.reader_may_resume = 0;
  TestMutexUnlock(&g_atomic_hook.mutex);
}

static int WaitForAtomicHookFlag(int* flag, const char* message) {
  for (unsigned attempt = 0; attempt < 5000u; ++attempt) {
    int observed;

    TestMutexLock(&g_atomic_hook.mutex);
    observed = *flag;
    TestMutexUnlock(&g_atomic_hook.mutex);
    if (observed) { return 1; }
    SleepMillis(1u);
  }
  Fail(message);
  return 0;
}

static int WaitForWriterBlocked(void) {
  return WaitForAtomicHookFlag(&g_atomic_hook.writer_blocked,
                               "writer election hook must observe the completion CAS");
}

static int WaitForReaderBlocked(void) {
  return WaitForAtomicHookFlag(&g_atomic_hook.reader_blocked,
                               "reader hook must capture the stale cold status");
}

static void ResumeWriter(void) {
  TestMutexLock(&g_atomic_hook.mutex);
  g_atomic_hook.writer_may_resume = 1;
  TestCondBroadcast(&g_atomic_hook.cond);
  TestMutexUnlock(&g_atomic_hook.mutex);
}

static void ResumeReader(void) {
  TestMutexLock(&g_atomic_hook.mutex);
  g_atomic_hook.reader_may_resume = 1;
  TestCondBroadcast(&g_atomic_hook.cond);
  TestMutexUnlock(&g_atomic_hook.mutex);
}

static inline void MaybeBlockAfterWriterElection(uint64_t* value, int exchanged) {
  if (!exchanged || g_thread_role != kThreadRoleWriter) { return; }

  TestMutexLock(&g_atomic_hook.mutex);
  if (!g_atomic_hook.enabled || value != g_atomic_hook.completion_address) {
    TestMutexUnlock(&g_atomic_hook.mutex);
    return;
  }
  if (!g_atomic_hook.writer_blocked) {
    g_atomic_hook.writer_blocked = 1;
    TestCondBroadcast(&g_atomic_hook.cond);
    while (!g_atomic_hook.writer_may_resume) {
      TestCondWait(&g_atomic_hook.cond, &g_atomic_hook.mutex);
    }
  }
  TestMutexUnlock(&g_atomic_hook.mutex);
}

static inline void MaybeBlockAfterReaderStatusLoad(const uint64_t* value, uint64_t observed) {
  if (g_thread_role != kThreadRoleReader) { return; }

  TestMutexLock(&g_atomic_hook.mutex);
  if (!g_atomic_hook.enabled || value != g_atomic_hook.status_address ||
      observed != g_atomic_hook.cold_status) {
    TestMutexUnlock(&g_atomic_hook.mutex);
    return;
  }
  if (!g_atomic_hook.reader_blocked) {
    g_atomic_hook.reader_blocked = 1;
    TestCondBroadcast(&g_atomic_hook.cond);
    while (!g_atomic_hook.reader_may_resume) {
      TestCondWait(&g_atomic_hook.cond, &g_atomic_hook.mutex);
    }
  }
  TestMutexUnlock(&g_atomic_hook.mutex);
}

static inline uint64_t ObfAtomicLoadU64Acquire(const uint64_t* value) {
  const uint64_t observed = ObfAtomicLoadU64AcquireBase(value);
  MaybeBlockAfterReaderStatusLoad(value, observed);
  return observed;
}

static inline int
ObfAtomicCompareExchangeU64AcqRelRelaxed(uint64_t* value, uint64_t* expected, uint64_t desired) {
  const int exchanged = ObfAtomicCompareExchangeU64AcqRelRelaxedBase(value, expected, desired);
  MaybeBlockAfterWriterElection(value, exchanged);
  return exchanged;
}

#include "../../runtime/string_auth_runtime.c"

enum DecodeKind {
  kDecodeKindString = 0,
  kDecodeKindConstantPool = 1,
};

struct StringFixture {
  struct ObfAuthenticatedBufferReferenceV3 destination_ref;
  struct ObfAuthenticatedBufferReferenceV3 ciphertext_ref;
  struct ObfAuthenticatedBufferReferenceV3 build_key_ref;
  struct ObfAuthenticatedStateReferenceV3 state_ref;
  struct ObfStringRuntimeDescriptorV3 descriptor;
  struct ObfAuthenticatedDecodeTopologyV3 topology;
  uint8_t destination[64];
  uint8_t ciphertext[64];
  uint8_t plaintext[64];
  uint8_t build_key[32];
  size_t length;
  uint64_t cold_status;
};

struct ConstantFixture {
  struct ObfAuthenticatedBufferReferenceV3 destination_ref;
  struct ObfAuthenticatedBufferReferenceV3 ciphertext_ref;
  struct ObfAuthenticatedBufferReferenceV3 build_key_ref;
  struct ObfAuthenticatedStateReferenceV3 state_ref;
  struct ObfConstantPoolRuntimeDescriptorV3 descriptor;
  struct ObfAuthenticatedDecodeTopologyV3 topology;
  uint8_t destination[64];
  uint8_t ciphertext[64];
  uint8_t plaintext[64];
  uint8_t build_key[32];
  size_t length;
  uint64_t cold_status;
};

struct DecodeThreadArgs {
  enum DecodeKind kind;
  void* fixture;
  struct TestStartGate* start_gate;
  enum ThreadRole role;
  uint8_t* result;
};

static void FillDeterministicBytes(uint8_t* output, size_t size, uint8_t seed) {
  for (size_t index = 0; index < size; ++index) {
    output[index] = (uint8_t)(seed + (uint8_t)(17u * (uint8_t)index) + (uint8_t)(index >> 1u));
  }
}

static void InitializeStringFixture(struct StringFixture* fixture) {
  uint8_t function_key[32];
  uint8_t site_key[32];
  uint8_t enc_key[32];
  uint8_t mac_key[32];

  memset(fixture, 0, sizeof(*fixture));
  fixture->length = 48u;
  FillDeterministicBytes(fixture->plaintext, fixture->length, 0x31u);
  FillDeterministicBytes(fixture->build_key, sizeof(fixture->build_key), 0x55u);
  FillDeterministicBytes(fixture->descriptor.nonce, sizeof(fixture->descriptor.nonce), 0x80u);
  memset(fixture->destination, 0xA5, sizeof(fixture->destination));

  fixture->destination_ref.target = fixture->destination;
  fixture->ciphertext_ref.target = fixture->ciphertext;
  fixture->build_key_ref.target = fixture->build_key;

  fixture->descriptor.version = kObfStringDescriptorVersionV3;
  fixture->descriptor.flags = kObfStringAuthFlagTrapOnFailure;
  fixture->descriptor.length = (uint64_t)fixture->length;
  fixture->descriptor.module_id = UINT64_C(0x1122334455667788);
  fixture->descriptor.function_id = UINT64_C(0x8877665544332211);
  fixture->descriptor.site_id = UINT64_C(0x13579bdf2468ace0);
  fixture->descriptor.binding_id = ObfDeriveStringBindingId(
      fixture->descriptor.module_id, fixture->descriptor.function_id, fixture->descriptor.site_id);
  fixture->descriptor.destination_capacity = (uint64_t)fixture->length;
  fixture->descriptor.ciphertext_capacity = (uint64_t)fixture->length;
  fixture->descriptor.build_key_capacity = kObfBuildKeyBytes;
  fixture->descriptor.destination = &fixture->destination_ref;
  fixture->descriptor.ciphertext = &fixture->ciphertext_ref;
  fixture->descriptor.build_key = &fixture->build_key_ref;
  fixture->descriptor.state = &fixture->state_ref;

  fixture->topology.descriptor = &fixture->descriptor;
  fixture->topology.destination_ref = &fixture->destination_ref;
  fixture->topology.destination_target = fixture->destination;
  fixture->topology.destination_capacity = fixture->descriptor.destination_capacity;
  fixture->topology.ciphertext_ref = &fixture->ciphertext_ref;
  fixture->topology.ciphertext_target = fixture->ciphertext;
  fixture->topology.ciphertext_capacity = fixture->descriptor.ciphertext_capacity;
  fixture->topology.build_key_ref = &fixture->build_key_ref;
  fixture->topology.build_key_target = fixture->build_key;
  fixture->topology.build_key_capacity = fixture->descriptor.build_key_capacity;
  fixture->topology.state_ref = &fixture->state_ref;

  ObfDeriveFunctionKey(function_key,
                       fixture->build_key,
                       fixture->descriptor.module_id,
                       fixture->descriptor.function_id);
  ObfDeriveSiteKey(site_key,
                   function_key,
                   kObfDomainString,
                   (uint32_t)sizeof(kObfDomainString),
                   fixture->descriptor.site_id);
  ObfDeriveLabeledKey(enc_key, site_key, kObfDomainEnc, (uint32_t)sizeof(kObfDomainEnc));
  ObfDeriveLabeledKey(mac_key, site_key, kObfDomainMac, (uint32_t)sizeof(kObfDomainMac));

  fixture->descriptor.build_key_cookie = fixture->build_key_ref.cookie =
      ObfDeriveBuildKeyCookie(fixture->build_key,
                              kObfAuthDescriptorKindString,
                              fixture->descriptor.binding_id,
                              fixture->descriptor.build_key_capacity);
  fixture->descriptor.destination_cookie = fixture->destination_ref.cookie =
      ObfDeriveReferenceCookie(mac_key,
                               kObfAuthDescriptorKindString,
                               fixture->descriptor.binding_id,
                               kObfAuthReferenceRoleDestination,
                               fixture->descriptor.destination_capacity);
  fixture->descriptor.ciphertext_cookie = fixture->ciphertext_ref.cookie =
      ObfDeriveReferenceCookie(mac_key,
                               kObfAuthDescriptorKindString,
                               fixture->descriptor.binding_id,
                               kObfAuthReferenceRoleCiphertext,
                               fixture->descriptor.ciphertext_capacity);
  fixture->descriptor.state_cookie = fixture->state_ref.cookie =
      ObfDeriveReferenceCookie(mac_key,
                               kObfAuthDescriptorKindString,
                               fixture->descriptor.binding_id,
                               kObfAuthReferenceRoleState,
                               0u);
  fixture->cold_status = ObfDeriveCacheColdStatus(mac_key,
                                                  kObfAuthDescriptorKindString,
                                                  fixture->descriptor.binding_id,
                                                  fixture->descriptor.destination_capacity,
                                                  fixture->descriptor.ciphertext_capacity,
                                                  fixture->descriptor.build_key_capacity);
  fixture->state_ref.status = fixture->cold_status;
  fixture->state_ref.completion = fixture->cold_status;

  ObfDecodePayload(
      fixture->ciphertext, fixture->plaintext, enc_key, fixture->descriptor.nonce, fixture->length);
  ObfComputeStringTag(
      fixture->descriptor.tag, mac_key, &fixture->descriptor, fixture->ciphertext, fixture->length);

  ObfSecureZeroize(function_key, sizeof(function_key));
  ObfSecureZeroize(site_key, sizeof(site_key));
  ObfSecureZeroize(enc_key, sizeof(enc_key));
  ObfSecureZeroize(mac_key, sizeof(mac_key));
}

static void InitializeConstantFixture(struct ConstantFixture* fixture) {
  uint8_t function_key[32];
  uint8_t pool_key[32];
  uint8_t enc_key[32];
  uint8_t mac_key[32];

  memset(fixture, 0, sizeof(*fixture));
  fixture->length = 40u;
  FillDeterministicBytes(fixture->plaintext, fixture->length, 0x47u);
  FillDeterministicBytes(fixture->build_key, sizeof(fixture->build_key), 0x6Bu);
  FillDeterministicBytes(fixture->descriptor.nonce, sizeof(fixture->descriptor.nonce), 0x21u);
  memset(fixture->destination, 0x5A, sizeof(fixture->destination));

  fixture->destination_ref.target = fixture->destination;
  fixture->ciphertext_ref.target = fixture->ciphertext;
  fixture->build_key_ref.target = fixture->build_key;

  fixture->descriptor.version = kObfConstantPoolDescriptorVersionV3;
  fixture->descriptor.flags = kObfConstantPoolAuthFlagTrapOnFailure;
  fixture->descriptor.length = (uint64_t)fixture->length;
  fixture->descriptor.module_id = UINT64_C(0x1021324354657687);
  fixture->descriptor.pool_id = UINT64_C(0x99aabbccddeeff01);
  fixture->descriptor.binding_id =
      ObfDeriveConstantPoolBindingId(fixture->descriptor.module_id, fixture->descriptor.pool_id);
  fixture->descriptor.destination_capacity = (uint64_t)fixture->length;
  fixture->descriptor.ciphertext_capacity = (uint64_t)fixture->length;
  fixture->descriptor.build_key_capacity = kObfBuildKeyBytes;
  fixture->descriptor.destination = &fixture->destination_ref;
  fixture->descriptor.ciphertext = &fixture->ciphertext_ref;
  fixture->descriptor.build_key = &fixture->build_key_ref;
  fixture->descriptor.state = &fixture->state_ref;

  fixture->topology.descriptor = &fixture->descriptor;
  fixture->topology.destination_ref = &fixture->destination_ref;
  fixture->topology.destination_target = fixture->destination;
  fixture->topology.destination_capacity = fixture->descriptor.destination_capacity;
  fixture->topology.ciphertext_ref = &fixture->ciphertext_ref;
  fixture->topology.ciphertext_target = fixture->ciphertext;
  fixture->topology.ciphertext_capacity = fixture->descriptor.ciphertext_capacity;
  fixture->topology.build_key_ref = &fixture->build_key_ref;
  fixture->topology.build_key_target = fixture->build_key;
  fixture->topology.build_key_capacity = fixture->descriptor.build_key_capacity;
  fixture->topology.state_ref = &fixture->state_ref;

  ObfDeriveFunctionKey(function_key, fixture->build_key, fixture->descriptor.module_id, 0u);
  ObfDeriveSiteKey(pool_key,
                   function_key,
                   kObfDomainConstant,
                   (uint32_t)sizeof(kObfDomainConstant),
                   fixture->descriptor.pool_id);
  ObfDeriveLabeledKey(enc_key, pool_key, kObfDomainEnc, (uint32_t)sizeof(kObfDomainEnc));
  ObfDeriveLabeledKey(mac_key, pool_key, kObfDomainMac, (uint32_t)sizeof(kObfDomainMac));

  fixture->descriptor.build_key_cookie = fixture->build_key_ref.cookie =
      ObfDeriveBuildKeyCookie(fixture->build_key,
                              kObfAuthDescriptorKindConstantPool,
                              fixture->descriptor.binding_id,
                              fixture->descriptor.build_key_capacity);
  fixture->descriptor.destination_cookie = fixture->destination_ref.cookie =
      ObfDeriveReferenceCookie(mac_key,
                               kObfAuthDescriptorKindConstantPool,
                               fixture->descriptor.binding_id,
                               kObfAuthReferenceRoleDestination,
                               fixture->descriptor.destination_capacity);
  fixture->descriptor.ciphertext_cookie = fixture->ciphertext_ref.cookie =
      ObfDeriveReferenceCookie(mac_key,
                               kObfAuthDescriptorKindConstantPool,
                               fixture->descriptor.binding_id,
                               kObfAuthReferenceRoleCiphertext,
                               fixture->descriptor.ciphertext_capacity);
  fixture->descriptor.state_cookie = fixture->state_ref.cookie =
      ObfDeriveReferenceCookie(mac_key,
                               kObfAuthDescriptorKindConstantPool,
                               fixture->descriptor.binding_id,
                               kObfAuthReferenceRoleState,
                               0u);
  fixture->cold_status = ObfDeriveCacheColdStatus(mac_key,
                                                  kObfAuthDescriptorKindConstantPool,
                                                  fixture->descriptor.binding_id,
                                                  fixture->descriptor.destination_capacity,
                                                  fixture->descriptor.ciphertext_capacity,
                                                  fixture->descriptor.build_key_capacity);
  fixture->state_ref.status = fixture->cold_status;
  fixture->state_ref.completion = fixture->cold_status;

  ObfDecodePayload(
      fixture->ciphertext, fixture->plaintext, enc_key, fixture->descriptor.nonce, fixture->length);
  ObfComputeConstantPoolTag(
      fixture->descriptor.tag, mac_key, &fixture->descriptor, fixture->ciphertext, fixture->length);

  ObfSecureZeroize(function_key, sizeof(function_key));
  ObfSecureZeroize(pool_key, sizeof(pool_key));
  ObfSecureZeroize(enc_key, sizeof(enc_key));
  ObfSecureZeroize(mac_key, sizeof(mac_key));
}

static void ResetStringFixture(struct StringFixture* fixture) {
  memset(fixture->destination, 0xA5, sizeof(fixture->destination));
  fixture->state_ref.status = fixture->cold_status;
  fixture->state_ref.completion = fixture->cold_status;
}

static void ResetConstantFixture(struct ConstantFixture* fixture) {
  memset(fixture->destination, 0x5A, sizeof(fixture->destination));
  fixture->state_ref.status = fixture->cold_status;
  fixture->state_ref.completion = fixture->cold_status;
}

static void VerifyStringDecoded(const struct StringFixture* fixture, const char* label) {
  struct ObfStringValidationContext context;
  uint64_t expected_completion;
  char message[160];

  memset(&context, 0, sizeof(context));
  if (!ObfValidateStringDescriptor(&context,
                                   &fixture->descriptor,
                                   fixture->descriptor.length,
                                   fixture->descriptor.binding_id,
                                   &fixture->topology)) {
    snprintf(message, sizeof(message), "%s: descriptor validation must succeed", label);
    Fail(message);
    return;
  }
  if (!ObfVerifyStringTag(&context, &fixture->descriptor)) {
    snprintf(message, sizeof(message), "%s: descriptor tag must remain valid", label);
    Fail(message);
    ObfSecureZeroize(&context, sizeof(context));
    return;
  }
  if (!ObfDeriveRelocationStatuses(&context.statuses,
                                   context.mac_key,
                                   kObfAuthDescriptorKindString,
                                   fixture->descriptor.binding_id,
                                   &fixture->descriptor,
                                   &fixture->topology,
                                   fixture->descriptor.state)) {
    snprintf(message, sizeof(message), "%s: relocation statuses must derive", label);
    Fail(message);
    ObfSecureZeroize(&context, sizeof(context));
    return;
  }
  expected_completion = ObfStringCompletion(&context, &fixture->descriptor, &fixture->topology);
  snprintf(message, sizeof(message), "%s: status must publish decoded token", label);
  ExpectU64Eq(fixture->state_ref.status, context.statuses.decoded, message);
  snprintf(message, sizeof(message), "%s: completion must publish decoded hash", label);
  ExpectU64Eq(fixture->state_ref.completion, expected_completion, message);
  snprintf(message, sizeof(message), "%s: destination must match plaintext", label);
  ExpectBufferEq(fixture->destination, fixture->plaintext, fixture->length, message);
  ObfSecureZeroize(&context, sizeof(context));
}

static void VerifyConstantDecoded(const struct ConstantFixture* fixture, const char* label) {
  struct ObfConstantPoolValidationContext context;
  uint64_t expected_completion;
  char message[160];

  memset(&context, 0, sizeof(context));
  if (!ObfValidateConstantPoolDescriptor(&context,
                                         &fixture->descriptor,
                                         fixture->descriptor.length,
                                         fixture->descriptor.binding_id,
                                         &fixture->topology)) {
    snprintf(message, sizeof(message), "%s: descriptor validation must succeed", label);
    Fail(message);
    return;
  }
  if (!ObfVerifyConstantPoolTag(&context, &fixture->descriptor)) {
    snprintf(message, sizeof(message), "%s: descriptor tag must remain valid", label);
    Fail(message);
    ObfSecureZeroize(&context, sizeof(context));
    return;
  }
  if (!ObfDeriveRelocationStatuses(&context.statuses,
                                   context.mac_key,
                                   kObfAuthDescriptorKindConstantPool,
                                   fixture->descriptor.binding_id,
                                   &fixture->descriptor,
                                   &fixture->topology,
                                   fixture->descriptor.state)) {
    snprintf(message, sizeof(message), "%s: relocation statuses must derive", label);
    Fail(message);
    ObfSecureZeroize(&context, sizeof(context));
    return;
  }
  expected_completion =
      ObfConstantPoolCompletion(&context, &fixture->descriptor, &fixture->topology);
  snprintf(message, sizeof(message), "%s: status must publish decoded token", label);
  ExpectU64Eq(fixture->state_ref.status, context.statuses.decoded, message);
  snprintf(message, sizeof(message), "%s: completion must publish decoded hash", label);
  ExpectU64Eq(fixture->state_ref.completion, expected_completion, message);
  snprintf(message, sizeof(message), "%s: destination must match plaintext", label);
  ExpectBufferEq(fixture->destination, fixture->plaintext, fixture->length, message);
  ObfSecureZeroize(&context, sizeof(context));
}

TEST_THREAD_PROC(DecodeThreadMain) {
  struct DecodeThreadArgs* args = (struct DecodeThreadArgs*)raw;

  g_thread_role = args->role;
  if (args->start_gate != NULL) { TestStartGateWait(args->start_gate); }
  if (args->kind == kDecodeKindString) {
    struct StringFixture* fixture = (struct StringFixture*)args->fixture;
    args->result = OBF_RT_STRING_AUTH_DECODE_V3(&fixture->descriptor,
                                                fixture->descriptor.length,
                                                fixture->descriptor.binding_id,
                                                &fixture->topology);
  } else {
    struct ConstantFixture* fixture = (struct ConstantFixture*)args->fixture;
    args->result = OBF_RT_CONSTANT_POOL_DECODE_V3(&fixture->descriptor,
                                                  fixture->descriptor.length,
                                                  fixture->descriptor.binding_id,
                                                  &fixture->topology);
  }
  g_thread_role = kThreadRoleNone;
#if defined(_WIN32)
  return 0;
#else
  return NULL;
#endif
}

static void TestDeterministicStringColdCompletionRace(void) {
  struct StringFixture fixture;
  struct DecodeThreadArgs writer_args;
  struct DecodeThreadArgs reader_args;
  TestThread writer_thread = 0;
  TestThread reader_thread = 0;

  InitializeStringFixture(&fixture);
  ResetStringFixture(&fixture);
  ConfigureAtomicHook(
      &fixture.state_ref.status, &fixture.state_ref.completion, fixture.cold_status);

  writer_args.kind = kDecodeKindString;
  writer_args.fixture = &fixture;
  writer_args.start_gate = NULL;
  writer_args.role = kThreadRoleWriter;
  writer_args.result = NULL;
  reader_args.kind = kDecodeKindString;
  reader_args.fixture = &fixture;
  reader_args.start_gate = NULL;
  reader_args.role = kThreadRoleReader;
  reader_args.result = NULL;

  if (!StartThread(
          &writer_thread, DecodeThreadMain, &writer_args, "string race writer thread must start")) {
    DisableAtomicHook();
    return;
  }
  if (!WaitForWriterBlocked()) {
    ReleaseAtomicHookWaiters();
    JoinThread(&writer_thread, "string race writer thread must join after timeout");
    DisableAtomicHook();
    return;
  }
  if (!StartThread(
          &reader_thread, DecodeThreadMain, &reader_args, "string race reader thread must start")) {
    ReleaseAtomicHookWaiters();
    JoinThread(&writer_thread, "string race writer thread must join after reader start failure");
    DisableAtomicHook();
    return;
  }
  if (!WaitForReaderBlocked()) {
    ReleaseAtomicHookWaiters();
    JoinThread(&writer_thread, "string race writer thread must join after reader timeout");
    JoinThread(&reader_thread, "string race reader thread must join after timeout");
    DisableAtomicHook();
    return;
  }

  ResumeWriter();
  JoinThread(&writer_thread, "string race writer thread must join");
  ResumeReader();
  JoinThread(&reader_thread, "string race reader thread must join");
  DisableAtomicHook();

  ExpectPtrEq(writer_args.result,
              fixture.destination,
              "string race writer must return the destination buffer");
  ExpectPtrEq(reader_args.result,
              fixture.destination,
              "string race reader must return the destination buffer");
  VerifyStringDecoded(&fixture, "string deterministic race");
}

static void TestDeterministicConstantColdCompletionRace(void) {
  struct ConstantFixture fixture;
  struct DecodeThreadArgs writer_args;
  struct DecodeThreadArgs reader_args;
  TestThread writer_thread = 0;
  TestThread reader_thread = 0;

  InitializeConstantFixture(&fixture);
  ResetConstantFixture(&fixture);
  ConfigureAtomicHook(
      &fixture.state_ref.status, &fixture.state_ref.completion, fixture.cold_status);

  writer_args.kind = kDecodeKindConstantPool;
  writer_args.fixture = &fixture;
  writer_args.start_gate = NULL;
  writer_args.role = kThreadRoleWriter;
  writer_args.result = NULL;
  reader_args.kind = kDecodeKindConstantPool;
  reader_args.fixture = &fixture;
  reader_args.start_gate = NULL;
  reader_args.role = kThreadRoleReader;
  reader_args.result = NULL;

  if (!StartThread(&writer_thread,
                   DecodeThreadMain,
                   &writer_args,
                   "constant race writer thread must start")) {
    DisableAtomicHook();
    return;
  }
  if (!WaitForWriterBlocked()) {
    ReleaseAtomicHookWaiters();
    JoinThread(&writer_thread, "constant race writer thread must join after timeout");
    DisableAtomicHook();
    return;
  }
  if (!StartThread(&reader_thread,
                   DecodeThreadMain,
                   &reader_args,
                   "constant race reader thread must start")) {
    ReleaseAtomicHookWaiters();
    JoinThread(&writer_thread, "constant race writer thread must join after reader start failure");
    DisableAtomicHook();
    return;
  }
  if (!WaitForReaderBlocked()) {
    ReleaseAtomicHookWaiters();
    JoinThread(&writer_thread, "constant race writer thread must join after reader timeout");
    JoinThread(&reader_thread, "constant race reader thread must join after timeout");
    DisableAtomicHook();
    return;
  }

  ResumeWriter();
  JoinThread(&writer_thread, "constant race writer thread must join");
  ResumeReader();
  JoinThread(&reader_thread, "constant race reader thread must join");
  DisableAtomicHook();

  ExpectPtrEq(writer_args.result,
              fixture.destination,
              "constant race writer must return the destination buffer");
  ExpectPtrEq(reader_args.result,
              fixture.destination,
              "constant race reader must return the destination buffer");
  VerifyConstantDecoded(&fixture, "constant deterministic race");
}

static void RunConcurrentStringStressRound(struct StringFixture* fixture,
                                           unsigned thread_count,
                                           unsigned round_index) {
  struct TestStartGate gate;
  struct DecodeThreadArgs* args;
  TestThread* threads;
  char message[160];

  ResetStringFixture(fixture);
  TestStartGateInit(&gate);
  args = (struct DecodeThreadArgs*)calloc(thread_count, sizeof(*args));
  threads = (TestThread*)calloc(thread_count, sizeof(*threads));
  if (args == NULL || threads == NULL) {
    free(args);
    free(threads);
    TestStartGateDestroy(&gate);
    Fail("string stress must allocate worker fixtures");
    return;
  }

  for (unsigned index = 0; index < thread_count; ++index) {
    args[index].kind = kDecodeKindString;
    args[index].fixture = fixture;
    args[index].start_gate = &gate;
    args[index].role = kThreadRoleNone;
    args[index].result = NULL;
    if (!StartThread(&threads[index],
                     DecodeThreadMain,
                     &args[index],
                     "string stress worker thread must start")) {
      TestStartGateRelease(&gate);
      for (unsigned join_index = 0; join_index < index; ++join_index) {
        JoinThread(&threads[join_index], "string stress started worker must join");
      }
      free(args);
      free(threads);
      TestStartGateDestroy(&gate);
      return;
    }
  }
  (void)WaitForStartGateReady(
      &gate, thread_count, "string stress workers must reach the shared start gate");
  TestStartGateRelease(&gate);

  for (unsigned index = 0; index < thread_count; ++index) {
    JoinThread(&threads[index], "string stress worker thread must join");
    snprintf(message,
             sizeof(message),
             "string stress round %u worker %u must return the destination buffer",
             round_index,
             index);
    ExpectPtrEq(args[index].result, fixture->destination, message);
  }

  VerifyStringDecoded(fixture, "string concurrent stress");
  free(args);
  free(threads);
  TestStartGateDestroy(&gate);
}

static void RunConcurrentConstantStressRound(struct ConstantFixture* fixture,
                                             unsigned thread_count,
                                             unsigned round_index) {
  struct TestStartGate gate;
  struct DecodeThreadArgs* args;
  TestThread* threads;
  char message[160];

  ResetConstantFixture(fixture);
  TestStartGateInit(&gate);
  args = (struct DecodeThreadArgs*)calloc(thread_count, sizeof(*args));
  threads = (TestThread*)calloc(thread_count, sizeof(*threads));
  if (args == NULL || threads == NULL) {
    free(args);
    free(threads);
    TestStartGateDestroy(&gate);
    Fail("constant stress must allocate worker fixtures");
    return;
  }

  for (unsigned index = 0; index < thread_count; ++index) {
    args[index].kind = kDecodeKindConstantPool;
    args[index].fixture = fixture;
    args[index].start_gate = &gate;
    args[index].role = kThreadRoleNone;
    args[index].result = NULL;
    if (!StartThread(&threads[index],
                     DecodeThreadMain,
                     &args[index],
                     "constant stress worker thread must start")) {
      TestStartGateRelease(&gate);
      for (unsigned join_index = 0; join_index < index; ++join_index) {
        JoinThread(&threads[join_index], "constant stress started worker must join");
      }
      free(args);
      free(threads);
      TestStartGateDestroy(&gate);
      return;
    }
  }
  (void)WaitForStartGateReady(
      &gate, thread_count, "constant stress workers must reach the shared start gate");
  TestStartGateRelease(&gate);

  for (unsigned index = 0; index < thread_count; ++index) {
    JoinThread(&threads[index], "constant stress worker thread must join");
    snprintf(message,
             sizeof(message),
             "constant stress round %u worker %u must return the destination buffer",
             round_index,
             index);
    ExpectPtrEq(args[index].result, fixture->destination, message);
  }

  VerifyConstantDecoded(fixture, "constant concurrent stress");
  free(args);
  free(threads);
  TestStartGateDestroy(&gate);
}

static void TestConcurrentStress(void) {
  enum {
    kStressThreadCount = 8,
    kStressRounds = 64,
  };
  struct StringFixture string_fixture;
  struct ConstantFixture constant_fixture;

  InitializeStringFixture(&string_fixture);
  InitializeConstantFixture(&constant_fixture);
  for (unsigned round = 0; round < kStressRounds; ++round) {
    RunConcurrentStringStressRound(&string_fixture, kStressThreadCount, round);
    RunConcurrentConstantStressRound(&constant_fixture, kStressThreadCount, round);
  }
}

int main(void) {
  InitializeAtomicHook();
  TestDeterministicStringColdCompletionRace();
  TestDeterministicConstantColdCompletionRace();
  TestConcurrentStress();
  DestroyAtomicHook();
  if (g_failures != 0) { return EXIT_FAILURE; }
  return EXIT_SUCCESS;
}
