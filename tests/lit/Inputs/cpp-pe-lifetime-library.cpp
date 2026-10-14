#ifndef BUILD_LIBRARY
#define BUILD_LIBRARY
#endif
#include "cpp-pe-lifetime-api.h"

#ifndef RAW_CONTROL
extern "C" __attribute__((noinline)) U lifetime_text(U stage) {
  static const char payload[] = "lifecycle-auth-v1-payload";
  return static_cast<unsigned char>(payload[stage % 25]);
}

extern "C" __attribute__((noinline)) U lifetime_vm(U stage, U previous, U text) {
  U mixed = stage * UINT64_C(0x100000001b3) + previous +
            UINT64_C(0x9e3779b97f4a7c15);
  return ((mixed << 11) | (mixed >> 53)) ^
         (text * UINT64_C(0xa0761d6478bd642f));
}

extern "C" __attribute__((noinline)) U lifetime_step(U stage, U *effect) {
  U text = lifetime_text(stage);
  U value = lifetime_vm(stage, *effect, text);
  *effect = value + stage * 13;
  return value ^ *effect;
}
#endif

namespace {
LifetimeLog *mapped_log = nullptr;
DWORD fls_index = FLS_OUT_OF_INDEXES;
volatile LONG active_fls = 0;
bool first_attempt_failed = false;

struct LogConnection {
  HANDLE mapping = nullptr;

  LogConnection() noexcept {
    wchar_t name[512];
    constexpr DWORD capacity = sizeof(name) / sizeof(name[0]);
    DWORD length = GetEnvironmentVariableW(L"OBF_CPP_LIFETIME_LOG", name, capacity);
    if (length == 0 || length >= capacity)
      return;
    mapping = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, name);
    if (!mapping)
      return;
    mapped_log = static_cast<LifetimeLog *>(MapViewOfFile(
        mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(LifetimeLog)));
    if (!mapped_log) {
      CloseHandle(mapping);
      mapping = nullptr;
    }
  }

  ~LogConnection() noexcept {
    if (mapped_log) {
      UnmapViewOfFile(mapped_log);
      mapped_log = nullptr;
    }
    if (mapping)
      CloseHandle(mapping);
  }
};

// The first ordinary C++ global keeps the log mapped through all destructors.
LogConnection connection;

// Retained native code supplies a relocation-free checksum sample, not events.
volatile U sampled_anchor_first = UINT64_C(0xe15bd312caf09763);
volatile U sampled_anchor_second = UINT64_C(0x8ebc6af09c88c6e3);
__attribute__((noinline, used)) U lifetime_sampled_sibling(U input) {
  U first = sampled_anchor_first;
  U second = sampled_anchor_second;
  return ((input ^ first) * UINT64_C(0x9e3779b97f4a7c15)) + (second >> 3);
}

U emit(unsigned stage) noexcept {
  U result = lifetime_step(stage, &mapped_log->effect);
  LONG position = mapped_log->count;
  Event &event = mapped_log->events[position];
  event.stage = stage;
  event.result = result;
  event.effect = mapped_log->effect;
  event.thread = GetCurrentThreadId();
  InterlockedExchange(&mapped_log->count, position + 1);
  return result;
}

struct Global {
  unsigned destruction_stage;

  Global(unsigned construction, unsigned destruction) noexcept
      : destruction_stage(destruction) {
    if (mapped_log)
      emit(construction);
  }

  ~Global() noexcept {
    if (mapped_log)
      emit(destruction_stage);
  }
};
Global global_first(GLOBAL_FIRST, GLOBAL_FIRST_DTOR);
Global global_second(GLOBAL_SECOND, GLOBAL_SECOND_DTOR);

struct RetryFailure {
  U payload;
};

struct FirstMember {
  bool committed = false;

  FirstMember() noexcept {
    emit(LOCAL_ATTEMPT);
    emit(MEMBER_FIRST);
  }

  ~FirstMember() noexcept {
    emit(committed ? MEMBER_FIRST_DTOR : LOCAL_ROLLBACK);
  }
};

struct SecondMember {
  SecondMember() {
    if (!first_attempt_failed) {
      first_attempt_failed = true;
      throw RetryFailure{UINT64_C(0x51)};
    }
    emit(MEMBER_SECOND);
  }

  ~SecondMember() noexcept { emit(MEMBER_SECOND_DTOR); }
};

struct Local {
  FirstMember first;
  SecondMember second;

  Local() {
    first.committed = true;
    emit(LOCAL_READY);
  }

  ~Local() noexcept { emit(LOCAL_DTOR); }
};

struct ThreadLifetime {
  unsigned destruction_stage;

  ThreadLifetime(unsigned construction, unsigned destruction) noexcept
      : destruction_stage(destruction) {
    emit(construction);
  }

  ~ThreadLifetime() noexcept { emit(destruction_stage); }
};

void WINAPI fls_cleanup(void *value) noexcept {
  if (!value)
    return;
  emit(FLS_DTOR);
  InterlockedDecrement(&active_fls);
}

constexpr DWORD seh_code = 0xe0425151UL;
} // namespace

extern "C" __attribute__((noinline)) void lifetime_local_initialize() {
  static Local local;
  (void)local;
}

API U lifetime_touch() {
  try {
    lifetime_local_initialize();
    static thread_local ThreadLifetime first(TLS_FIRST, TLS_FIRST_DTOR);
    static thread_local ThreadLifetime second(TLS_SECOND, TLS_SECOND_DTOR);
    (void)first;
    (void)second;
    return emit(TOUCH);
  } catch (const RetryFailure &failure) {
    if (failure.payload != UINT64_C(0x51))
      throw;
    emit(LOCAL_CATCH);
    return UINT64_MAX;
  }
}

API U lifetime_snapshot() { return mapped_log->effect; }

API int lifetime_fls_enter() {
  if (fls_index == FLS_OUT_OF_INDEXES) {
    fls_index = FlsAlloc(fls_cleanup);
    if (fls_index == FLS_OUT_OF_INDEXES)
      return 0;
  }
  if (FlsGetValue(fls_index))
    return 0;
  if (!FlsSetValue(fls_index, &fls_index))
    return 0;
  InterlockedIncrement(&active_fls);
  emit(FLS_READY);
  return 1;
}

API int lifetime_fls_leave() {
  if (fls_index == FLS_OUT_OF_INDEXES)
    return 0;
  void *value = FlsGetValue(fls_index);
  if (!value || !FlsSetValue(fls_index, nullptr))
    return 0;
  fls_cleanup(value);
  return 1;
}

API int lifetime_shutdown() {
  if (InterlockedCompareExchange(&active_fls, 0, 0) != 0)
    return 0;
  if (fls_index == FLS_OUT_OF_INDEXES)
    return 1;
  if (!FlsFree(fls_index))
    return 0;
  fls_index = FLS_OUT_OF_INDEXES;
  return 1;
}

API U lifetime_seh() {
  __try {
    RaiseException(seh_code, 0, 0, nullptr);
  } __except (GetExceptionCode() == seh_code ? EXCEPTION_EXECUTE_HANDLER
                                           : EXCEPTION_CONTINUE_SEARCH) {
    return emit(SEH_CAUGHT);
  }
  return UINT64_MAX;
}

API U lifetime_worker(HANDLE ready, HANDLE stop) {
  emit(WORK_READY);
  if (!SetEvent(ready) || WaitForSingleObject(stop, INFINITE) != WAIT_OBJECT_0)
    return UINT64_MAX;
  return emit(WORK_STOP);
}

extern "C" BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
  (void)module;
  if (reason == DLL_PROCESS_ATTACH) {
    if (!mapped_log)
      return FALSE;
    emit(ATTACH);
#ifdef FAIL_ATTACH
    return FALSE;
#endif
  } else if (reason == DLL_PROCESS_DETACH && mapped_log) {
    emit(reserved ? DETACH_PROCESS : DETACH_DYNAMIC);
  }
  return TRUE;
}
