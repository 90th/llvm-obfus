#include "cpp-pe-lifetime-api.h"

#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <limits>

#if !defined(_WIN32) || !defined(_M_X64)
#error "The lifetime host requires native Windows x64."
#endif

namespace {
constexpr DWORD timeout_ms = 20000;
constexpr U failed_touch = std::numeric_limits<U>::max();

[[noreturn]] void fail(const char *format, ...) {
  std::fputs("PE lifetime host: ", stderr);
  va_list args;
  va_start(args, format);
  std::vfprintf(stderr, format, args);
  va_end(args);
  std::fprintf(stderr, " (Win32 error %lu)\n", GetLastError());
  // Never unwind through a live DLL after a synchronization/assertion failure.
  ExitProcess(3);
}

void check(bool condition, const char *message) {
  if (!condition)
    fail("%s", message);
}

void wait(HANDLE handle) {
  check(WaitForSingleObject(handle, timeout_ms) == WAIT_OBJECT_0,
        "wait did not complete");
}

void close(HANDLE handle) {
  check(CloseHandle(handle) != 0, "CloseHandle");
}

HANDLE signal_handle() {
  HANDLE handle = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  check(handle != nullptr, "CreateEventW");
  return handle;
}

void signal(HANDLE handle) {
  check(SetEvent(handle) != 0, "SetEvent");
}

struct Step { U result; U effect; };

// Numeric bytes and separately expressed rotation arithmetic are independent of
// both the protected implementation and its raw oracle translation unit.
Step oracle(unsigned stage, U previous) {
  constexpr unsigned char bytes[] = {
      108, 105, 102, 101, 99, 121, 99, 108, 101, 45, 97, 117, 116,
      104, 45, 118, 49, 45, 112, 97, 121, 108, 111, 97, 100};
  const U sum = previous + UINT64_C(0x9e3779b97f4a7c15) +
                U(stage) * UINT64_C(0x100000001b3);
  const U rotated = (sum >> 53) | (sum << 11);
  const U value = rotated ^ (U(bytes[stage % 25]) * UINT64_C(0xa0761d6478bd642f));
  const U effect = value + U(stage) * 13;
  return {value ^ effect, effect};
}

struct Expected {
  unsigned count = 0;
  U effect = 0;
  Event events[256]{};

  U add(unsigned stage, DWORD thread) {
    check(count < 256, "expected event capacity");
    const Step step = oracle(stage, effect);
    effect = step.effect;
    events[count++] = Event{stage, step.result, effect, thread};
    return step.result;
  }

  void verify(const LifetimeLog *log, const char *point) const {
    const LONG actual = InterlockedCompareExchange(
        const_cast<volatile LONG *>(&log->count), 0, 0);
    if (actual != LONG(count) || log->effect != effect)
      fail("%s: expected count %u/effect %" PRIu64 ", got %ld/%" PRIu64,
           point, count, effect, actual, log->effect);
    for (unsigned i = 0; i != count; ++i) {
      const Event &a = log->events[i];
      const Event &e = events[i];
      if (a.stage != e.stage || a.result != e.result || a.effect != e.effect ||
          a.thread != e.thread)
        fail("%s: event %u differs (stage %u/%u, result %" PRIu64 "/%" PRIu64
             ", effect %" PRIu64 "/%" PRIu64 ", thread %lu/%lu)",
             point, i, a.stage, e.stage, a.result, e.result, a.effect, e.effect,
             a.thread, e.thread);
    }
  }
};

void attached(Expected &e, DWORD thread) {
  e.add(GLOBAL_FIRST, thread);
  e.add(GLOBAL_SECOND, thread);
  e.add(ATTACH, thread);
}

void failed_local(Expected &e, DWORD thread) {
  e.add(LOCAL_ATTEMPT, thread);
  e.add(MEMBER_FIRST, thread);
  e.add(LOCAL_ROLLBACK, thread);
  e.add(LOCAL_CATCH, thread);
}

U initialized_local(Expected &e, DWORD thread) {
  e.add(LOCAL_ATTEMPT, thread);
  e.add(MEMBER_FIRST, thread);
  e.add(MEMBER_SECOND, thread);
  e.add(LOCAL_READY, thread);
  e.add(TLS_FIRST, thread);
  e.add(TLS_SECOND, thread);
  return e.add(TOUCH, thread);
}

void tls_destroyed(Expected &e, DWORD thread) {
  e.add(TLS_SECOND_DTOR, thread);
  e.add(TLS_FIRST_DTOR, thread);
}

void detached(Expected &e, DWORD thread, bool local, bool process = false) {
  e.add(process ? DETACH_PROCESS : DETACH_DYNAMIC, thread);
  if (local) {
    e.add(LOCAL_DTOR, thread);
    e.add(MEMBER_SECOND_DTOR, thread);
    e.add(MEMBER_FIRST_DTOR, thread);
  }
  e.add(GLOBAL_SECOND_DTOR, thread);
  e.add(GLOBAL_FIRST_DTOR, thread);
}

struct Mapping {
  HANDLE handle = nullptr;
  LifetimeLog *log = nullptr;

  void create(unsigned generation) {
    wchar_t name[160];
    std::swprintf(name, 160, L"Local\\obf-cpp-lifetime-%lu-%llu-%u",
                  GetCurrentProcessId(),
                  static_cast<unsigned long long>(GetTickCount64()), generation);
    handle = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
                                sizeof(LifetimeLog), name);
    check(handle != nullptr && GetLastError() != ERROR_ALREADY_EXISTS,
          "creating fresh shared log");
    log = static_cast<LifetimeLog *>(MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0,
                                                  0, sizeof(LifetimeLog)));
    check(log != nullptr, "mapping shared log");
    std::memset(log, 0, sizeof(*log));
    check(SetEnvironmentVariableW(L"OBF_CPP_LIFETIME_LOG", name) != 0,
          "setting shared log environment");
  }

  void open_child() {
    wchar_t name[160];
    const DWORD length = GetEnvironmentVariableW(L"OBF_CPP_LIFETIME_LOG", name, 160);
    check(length != 0 && length < 160, "child shared log name");
    handle = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
    check(handle != nullptr, "opening parent shared log");
    log = static_cast<LifetimeLog *>(MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0,
                                                  0, sizeof(LifetimeLog)));
    check(log != nullptr, "mapping parent shared log");
  }

  void release() {
    check(SetEnvironmentVariableW(L"OBF_CPP_LIFETIME_LOG", nullptr) != 0,
          "clearing shared log environment");
    check(UnmapViewOfFile(log) != 0, "unmapping host shared log");
    log = nullptr;
    close(handle);
    handle = nullptr;
  }
};

using ValueFn = U (*)();
using StatusFn = int (*)();
using WorkFn = U (*)(HANDLE, HANDLE);
struct Api {
  ValueFn touch = nullptr;
  ValueFn snapshot = nullptr;
  StatusFn fls_enter = nullptr;
  StatusFn fls_leave = nullptr;
  StatusFn shutdown = nullptr;
  ValueFn seh = nullptr;
  WorkFn worker = nullptr;
};

template <typename T> T lookup(HMODULE module, const char *name) {
  FARPROC address = GetProcAddress(module, name);
  if (!address)
    fail("missing exact export %s", name);
  return reinterpret_cast<T>(address);
}

void unwind_entry(HMODULE module, ValueFn function) {
  const DWORD64 address = reinterpret_cast<DWORD64>(function);
  DWORD64 base = 0;
  PRUNTIME_FUNCTION entry = RtlLookupFunctionEntry(address, &base, nullptr);
  check(entry != nullptr && base == reinterpret_cast<DWORD64>(module),
        "native EH/SEH export has no image unwind entry");
  check(address >= base + entry->BeginAddress && address < base + entry->EndAddress &&
            entry->UnwindData != 0,
        "native EH/SEH unwind range does not cover export");
}

Api api_for(HMODULE module) {
  Api api;
  api.touch = lookup<ValueFn>(module, "lifetime_touch");
  api.snapshot = lookup<ValueFn>(module, "lifetime_snapshot");
  api.fls_enter = lookup<StatusFn>(module, "lifetime_fls_enter");
  api.fls_leave = lookup<StatusFn>(module, "lifetime_fls_leave");
  api.shutdown = lookup<StatusFn>(module, "lifetime_shutdown");
  api.seh = lookup<ValueFn>(module, "lifetime_seh");
  api.worker = lookup<WorkFn>(module, "lifetime_worker");
  unwind_entry(module, api.touch);
  unwind_entry(module, api.seh);
  return api;
}

bool is_loaded(const wchar_t *image) {
  const wchar_t *name = std::wcsrchr(image, L'\\');
  name = name ? name + 1 : image;
  return GetModuleHandleW(name) != nullptr;
}

void mapped(HMODULE module) {
  MEMORY_BASIC_INFORMATION info{};
  check(VirtualQuery(module, &info, sizeof(info)) == sizeof(info) &&
            info.State == MEM_COMMIT && info.Type == MEM_IMAGE &&
            info.AllocationBase == module,
        "DLL does not have its own image mapping");
}

void unmapped(const wchar_t *image, const void *old_base) {
  check(!is_loaded(image), "GetModuleHandleW retained the unloaded DLL");
  MEMORY_BASIC_INFORMATION info{};
  check(VirtualQuery(old_base, &info, sizeof(info)) == sizeof(info),
        "VirtualQuery after final release");
  check(info.Type != MEM_IMAGE || info.AllocationBase != old_base,
        "VirtualQuery retained the old DLL image mapping");
}

HMODULE extra_reference(HMODULE module, const void *address) {
  HMODULE reference = nullptr;
  // FROM_ADDRESS takes an ordinary reference. PIN would invalidate unload proof.
  check(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                          reinterpret_cast<LPCWSTR>(address), &reference) != 0 &&
            reference == module,
        "acquiring ordinary FROM_ADDRESS module reference");
  return reference;
}

struct Worker {
  ValueFn touch = nullptr;
  StatusFn enter = nullptr;
  StatusFn leave = nullptr;
  StatusFn shutdown = nullptr;
  WorkFn work = nullptr;
  HANDLE ready = nullptr;
  HANDLE stop = nullptr;
  HANDLE drained = nullptr;
  HANDLE finish = nullptr;
  U result = 0;
  DWORD thread = 0;
};

DWORD WINAPI tls_thread(void *opaque) {
  Worker &w = *static_cast<Worker *>(opaque);
  w.thread = GetCurrentThreadId();
  w.result = w.touch();
  w.touch = nullptr;
  signal(w.ready);
  // Host code alone waits; native TLS cleanup happens as this thread exits.
  wait(w.stop);
  return 0;
}

DWORD WINAPI fls_thread(void *opaque) {
  Worker &w = *static_cast<Worker *>(opaque);
  w.thread = GetCurrentThreadId();
  check(w.enter() == 1 && w.enter() == 0, "FLS enter/repeated enter statuses");
  check(w.shutdown() == 0, "FLS shutdown did not reject a live slot");
  signal(w.ready);
  wait(w.stop);
  check(w.leave() == 1 && w.leave() == 0, "FLS leave/repeated leave statuses");
  check(w.shutdown() == 1 && w.shutdown() == 1, "FLS shutdown statuses");
  w.enter = nullptr;
  w.leave = nullptr;
  w.shutdown = nullptr;
  signal(w.drained);
  // This thread outlives unmapping, with no DLL pointer, FLS callback, or TLS dtor.
  wait(w.finish);
  return 0;
}

DWORD WINAPI work_thread(void *opaque) {
  Worker &w = *static_cast<Worker *>(opaque);
  w.thread = GetCurrentThreadId();
  w.result = w.work(w.ready, w.stop);
  w.work = nullptr;
  return 0;
}

struct Outcome {
  unsigned count = 0;
  U effect = 0;
  Event events[256]{};
  bool extra_reference = false;
  bool retained_after_app_close = false;
  bool thread_outlived_unload = false;
  bool process_termination = false;
  bool failed_attach = false;
};

void copy_log(Outcome &out, const LifetimeLog *log) {
  out.count = static_cast<unsigned>(log->count);
  check(out.count <= 256, "observed event capacity");
  out.effect = log->effect;
  for (unsigned i = 0; i != out.count; ++i)
    out.events[i] = log->events[i];
}

void dynamic_cycle(const wchar_t *image, const char *mode, unsigned cycle,
                   Outcome &out) {
  check(!is_loaded(image), "DLL present before fresh load");
  Mapping mapping;
  mapping.create(cycle);
  const DWORD main_thread = GetCurrentThreadId();
  Expected e;
  HMODULE module = LoadLibraryW(image);
  check(module != nullptr, "LoadLibraryW");
  mapped(module);
  Api api = api_for(module);
  attached(e, main_thread);
  e.verify(mapping.log, "global construction/attach");
  const bool runtime = std::strcmp(mode, "runtime") == 0;
  const bool tls = std::strcmp(mode, "tls") == 0;
  const bool fls = std::strcmp(mode, "fls") == 0;
  const bool worker = std::strcmp(mode, "worker") == 0;
  check(runtime || tls || fls || worker, "unknown dynamic mode");
  if (runtime || tls) {
    check(api.touch() == failed_touch, "failed local initialization return");
    failed_local(e, main_thread);
    e.verify(mapping.log, "failed local initialization rollback");
  }
  check(api.seh() == e.add(SEH_CAUGHT, main_thread), "SEH result");
  e.verify(mapping.log, "native SEH catch");
  const void *old_base = module;
  if (runtime) {
    check(api.touch() == initialized_local(e, main_thread), "local retry return");
    e.verify(mapping.log, "local retry and main-thread native TLS");
    check(api.touch() == e.add(TOUCH, main_thread), "repeated local touch return");
    check(api.snapshot() == e.effect, "runtime snapshot");
    check(api.shutdown() == 1, "runtime shutdown");
    e.verify(mapping.log, "before runtime final release");
    api = {};
    check(FreeLibrary(module) != 0, "runtime final FreeLibrary");
    module = nullptr;
    tls_destroyed(e, main_thread);
    detached(e, main_thread, true);
  } else {
    Worker w;
    w.ready = signal_handle();
    w.stop = signal_handle();
    w.drained = signal_handle();
    w.finish = signal_handle();
    HMODULE reference = extra_reference(module, reinterpret_cast<const void *>(
        worker ? reinterpret_cast<FARPROC>(api.worker) :
                 reinterpret_cast<FARPROC>(api.touch)));
    out.extra_reference = true;
    LPTHREAD_START_ROUTINE entry = nullptr;
    if (tls) {
      w.touch = api.touch;
      entry = tls_thread;
    } else if (fls) {
      w.enter = api.fls_enter;
      w.leave = api.fls_leave;
      w.shutdown = api.shutdown;
      entry = fls_thread;
    } else {
      w.work = api.worker;
      entry = work_thread;
    }
    HANDLE thread = CreateThread(nullptr, 0, entry, &w, 0, nullptr);
    check(thread != nullptr, "CreateThread");
    wait(w.ready);
    if (tls)
      check(w.result == initialized_local(e, w.thread), "worker local retry return");
    else
      e.add(fls ? FLS_READY : WORK_READY, w.thread);
    e.verify(mapping.log, "worker readiness");
    check(api.snapshot() == e.effect, "worker readiness snapshot");
    check(FreeLibrary(module) != 0, "initial application FreeLibrary");
    module = nullptr;
    check(is_loaded(image), "ordinary extra reference did not preserve image");
    mapped(reference);
    out.retained_after_app_close = true;
    signal(w.stop);
    if (fls) {
      wait(w.drained);
      e.add(FLS_DTOR, w.thread);
      e.verify(mapping.log, "explicit FLS drain");
      check(WaitForSingleObject(thread, 0) == WAIT_TIMEOUT,
            "FLS host thread exited before final unload");
    } else {
      wait(thread);
      if (tls)
        tls_destroyed(e, w.thread);
      else
        check(w.result == e.add(WORK_STOP, w.thread), "in-flight work return");
      e.verify(mapping.log, "worker exit before final release");
    }
    check(api.shutdown() == 1, "pre-unload shutdown");
    // No exported function pointer survives the final release, even in host
    // worker storage whose thread deliberately remains alive in FLS mode.
    api = {};
    w.touch = nullptr;
    w.enter = nullptr;
    w.leave = nullptr;
    w.shutdown = nullptr;
    w.work = nullptr;
    check(FreeLibrary(reference) != 0, "final ordinary reference FreeLibrary");
    reference = nullptr;
    detached(e, main_thread, tls);
    unmapped(image, old_base);
    e.verify(mapping.log, "final unload before parked host thread exit");
    if (fls) {
      out.thread_outlived_unload = true;
      signal(w.finish);
      wait(thread);
      e.verify(mapping.log, "parked host thread exit after unmapping");
    }
    close(thread);
    close(w.ready);
    close(w.stop);
    close(w.drained);
    close(w.finish);
  }
  unmapped(image, old_base);
  e.verify(mapping.log, "complete dynamic destructor LIFO");
  copy_log(out, mapping.log);
  mapping.release();
}

void failed_attach_cycle(const wchar_t *image, unsigned cycle, Outcome &out) {
  check(!is_loaded(image), "failed-attach DLL present before load");
  Mapping mapping;
  mapping.create(cycle);
  SetLastError(ERROR_SUCCESS);
  HMODULE module = LoadLibraryW(image);
  check(module == nullptr, "failed attach unexpectedly returned a module");
  check(GetLastError() == ERROR_DLL_INIT_FAILED, "failed attach error category");
  check(!is_loaded(image), "failed attach retained module handle");
  Expected e;
  const DWORD thread = GetCurrentThreadId();
  attached(e, thread);
  detached(e, thread, false);
  e.verify(mapping.log, "failed attach reverse global cleanup");
  out.failed_attach = true;
  copy_log(out, mapping.log);
  mapping.release();
}

[[noreturn]] void termination_child(const wchar_t *image) {
  Mapping mapping;
  mapping.open_child();
  HMODULE module = LoadLibraryW(image);
  check(module != nullptr, "termination child LoadLibraryW");
  Api api = api_for(module);
  Expected e;
  const DWORD main_thread = GetCurrentThreadId();
  attached(e, main_thread);
  check(api.touch() == failed_touch, "termination failed local return");
  failed_local(e, main_thread);
  check(api.seh() == e.add(SEH_CAUGHT, main_thread), "termination SEH return");
  check(api.touch() == initialized_local(e, main_thread), "termination main TLS return");
  Worker w;
  w.touch = api.touch;
  w.ready = signal_handle();
  w.stop = signal_handle();
  HANDLE thread = CreateThread(nullptr, 0, tls_thread, &w, 0, nullptr);
  check(thread != nullptr, "termination CreateThread");
  wait(w.ready);
  e.add(TLS_FIRST, w.thread);
  e.add(TLS_SECOND, w.thread);
  check(w.result == e.add(TOUCH, w.thread), "termination worker TLS return");
  check(api.fls_enter() == 1, "termination main FLS enter");
  e.add(FLS_READY, main_thread);
  e.verify(mapping.log, "termination armed main and dormant worker");
  check(WaitForSingleObject(thread, 0) == WAIT_TIMEOUT,
        "termination worker must still be alive");
  api = {};
  // No join: ExitProcess can skip other-thread TLS. Waiting from DLL detach
  // would deadlock under the loader lock and is not part of this contract.
  ExitProcess(0);
}

void termination_cycle(const wchar_t *image, unsigned cycle, Outcome &out) {
  Mapping mapping;
  mapping.create(cycle);
  wchar_t executable[32768];
  const DWORD length = GetModuleFileNameW(nullptr, executable, 32768);
  check(length != 0 && length < 32768, "termination host executable path");
  wchar_t command[65536];
  const int written = std::swprintf(command, 65536, L"\"%ls\" \"%ls\" --termination-child",
                                    executable, image);
  check(written > 0 && written < 65536, "termination child command");
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  check(CreateProcessW(executable, command, nullptr, nullptr, FALSE, 0, nullptr,
                       nullptr, &startup, &process) != 0,
        "CreateProcessW termination child");
  wait(process.hProcess);
  DWORD code = 0;
  check(GetExitCodeProcess(process.hProcess, &code) != 0 && code == 0,
        "termination child exit status");
  close(process.hThread);
  close(process.hProcess);
  check(mapping.log->count > 16, "termination child did not construct both TLS instances");
  const DWORD main_thread = mapping.log->events[0].thread;
  Expected e;
  attached(e, main_thread);
  failed_local(e, main_thread);
  e.add(SEH_CAUGHT, main_thread);
  initialized_local(e, main_thread);
  const DWORD worker_thread = mapping.log->events[e.count].thread;
  check(main_thread != 0 && worker_thread != 0 && main_thread != worker_thread,
        "termination thread identities");
  e.add(TLS_FIRST, worker_thread);
  e.add(TLS_SECOND, worker_thread);
  e.add(TOUCH, worker_thread);
  e.add(FLS_READY, main_thread);
  e.add(FLS_DTOR, main_thread);
  tls_destroyed(e, main_thread);
  detached(e, main_thread, true, true);
  e.verify(mapping.log, "process termination main-only TLS and destructor LIFO");
  out.process_termination = true;
  copy_log(out, mapping.log);
  mapping.release();
}

void print_outcome(const Outcome &out, unsigned cycle) {
  std::printf("{\"generation\":%u,\"effect\":%" PRIu64
              ",\"extra_reference\":%s,\"retained_after_app_close\":%s,"
              "\"thread_outlived_unload\":%s,\"process_termination\":%s,"
              "\"failed_attach\":%s,\"events\":[",
              cycle, out.effect, out.extra_reference ? "true" : "false",
              out.retained_after_app_close ? "true" : "false",
              out.thread_outlived_unload ? "true" : "false",
              out.process_termination ? "true" : "false",
              out.failed_attach ? "true" : "false");
  for (unsigned i = 0; i != out.count; ++i) {
    const Event &event = out.events[i];
    std::printf("%s{\"stage\":%u,\"result\":%" PRIu64 ",\"effect\":%" PRIu64
                ",\"thread\":%lu}", i ? "," : "", event.stage, event.result,
                event.effect, event.thread);
  }
  std::fputs("]}", stdout);
}
} // namespace

int wmain(int argc, wchar_t **argv) {
  check(argc == 3, "usage: host <absolute DLL path> <mode>");
  // Avoid interactive loader/crash dialogs in native automation.
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
  if (std::wcscmp(argv[2], L"--termination-child") == 0)
    termination_child(argv[1]);
  char mode[32];
  const size_t converted = std::wcstombs(mode, argv[2], sizeof(mode));
  check(converted != size_t(-1) && converted < sizeof(mode), "mode conversion");
  Outcome outcomes[3]{};
  for (unsigned cycle = 0; cycle != 3; ++cycle) {
    if (std::strcmp(mode, "termination") == 0)
      termination_cycle(argv[1], cycle, outcomes[cycle]);
    else if (std::strcmp(mode, "failed_attach") == 0)
      failed_attach_cycle(argv[1], cycle, outcomes[cycle]);
    else
      dynamic_cycle(argv[1], mode, cycle, outcomes[cycle]);
  }
  std::printf("{\"ok\":true,\"mode\":\"%s\",\"generations\":[", mode);
  for (unsigned cycle = 0; cycle != 3; ++cycle) {
    if (cycle)
      std::fputc(',', stdout);
    print_outcome(outcomes[cycle], cycle);
  }
  std::fputs("]}\n", stdout);
  return 0;
}
