#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "cross-dso-string-copy-api.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <string>

static const char *const expected[2][3] = {
    {"amber producer A owns this copy", "A: independent data 1847", ""},
    {"violet producer B has another payload", "B: distinct data 9263", ""}};
static thread_local unsigned checks, statuses[4], reads;

static void require(bool condition, const char *message) {
  if (!condition) {
    std::fprintf(stderr, "copy exchange failure: %s (Win32=%lu)\n", message,
                 static_cast<unsigned long>(GetLastError()));
    std::exit(1);
  }
  ++checks;
}

struct Image {
  HMODULE handle;
  std::wstring path;
};

static Image load_image(const wchar_t *path) {
  wchar_t resolved[32768];
  DWORD length = GetFullPathNameW(path, 32768, resolved, nullptr);
  require(length > 0 && length < 32768, "resolving absolute image path");
  Image image{LoadLibraryExW(resolved, nullptr,
                            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
                                LOAD_LIBRARY_SEARCH_DEFAULT_DIRS), resolved};
  require(image.handle != nullptr, "loading native DLL with normal CRT startup");
  require(GetModuleHandleW(image.path.c_str()) == image.handle,
          "loaded DLL not found by full path");
  return image;
}

static bool symbol_is_owned_by(const Image &image, const void *symbol) {
  HMODULE owner = nullptr;
  MEMORY_BASIC_INFORMATION memory{};
  // UNCHANGED_REFCOUNT is essential: checking identity must not pin the DLL or
  // acquire a hidden reference that could invalidate the FreeLibrary proof.
  return symbol != nullptr &&
         GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(symbol), &owner) != 0 &&
         owner == image.handle &&
         VirtualQuery(symbol, &memory, sizeof(memory)) == sizeof(memory) &&
         memory.Type == MEM_IMAGE && memory.AllocationBase == image.handle;
}

static FARPROC owned_symbol(const Image &image, const char *name) {
  FARPROC symbol = GetProcAddress(image.handle, name);
  require(symbol != nullptr, "missing handle-scoped export");
  require(symbol_is_owned_by(image, reinterpret_cast<const void *>(symbol)),
          "export resolved to the wrong image owner");
  return symbol;
}

static int checked_copy(const Image &owner, copy_accessor accessor, uint32_t id,
                        char *destination, size_t capacity, size_t *required) {
  if (!symbol_is_owned_by(owner, reinterpret_cast<const void *>(accessor)))
    return -1;
  return accessor(id, destination, capacity, required);
}

static void unload_image(Image &image) {
  HMODULE handle = image.handle;
  image.handle = nullptr;
  require(FreeLibrary(handle) != 0, "FreeLibrary failed");
  require(GetModuleHandleW(image.path.c_str()) == nullptr,
          "DLL mapping survived actual FreeLibrary");
  MEMORY_BASIC_INFORMATION memory{};
  require(VirtualQuery(handle, &memory, sizeof(memory)) == sizeof(memory) &&
              memory.State == MEM_FREE,
          "image allocation survived FreeLibrary address-space inspection");
}

static void status_is(int actual, int status) {
  require(actual == status, "incorrect accessor status");
  ++statuses[status];
}

static void unchanged(const unsigned char *bytes, size_t count) {
  for (size_t index = 0; index < count; ++index)
    require(bytes[index] == 0xa6, "accessor wrote a destination sentinel");
}

static uint64_t consume(byte_reader reader, const unsigned char *bytes,
                        size_t count, uint64_t salt,
                        uint64_t *effect_buffer = nullptr) {
  uint64_t weighted = 0;
  for (size_t index = 0; index < count; ++index)
    weighted += static_cast<uint64_t>(bytes[index]) * (index + 1);
  uint64_t oracle = (UINT64_C(0x13579bdf) ^ salt) + weighted +
                    salt * count * (static_cast<uint64_t>(count) + 1) / 2;
  uint64_t effect = UINT64_C(0xdecafbad);
  if (effect_buffer == nullptr)
    effect_buffer = &effect;
  *effect_buffer = UINT64_C(0xdecafbad);
  uint64_t actual = reader(bytes, count, salt, effect_buffer);
  require(actual == oracle, "consumer returned incorrect byte arithmetic");
  require(*effect_buffer == (oracle ^ (salt << 1)),
          "consumer wrote incorrect effect");
  ++reads;
  return actual;
}

static void rejected_calls(copy_accessor accessor, unsigned variant, unsigned id,
                           unsigned char *buffer, size_t *required) {
  size_t length = std::strlen(expected[variant][id - 1]) + 1;
  *required = SIZE_MAX;
  status_is(accessor(id, nullptr, 0, required), COPY_NEED_CAPACITY);
  require(*required == length, "query lost exact required size");
  status_is(accessor(id, reinterpret_cast<char *>(buffer), length - 1, required),
            COPY_NEED_CAPACITY);
  require(*required == length, "short copy lost exact required size");
  unchanged(buffer, COPY_BUFFER_SIZE);
  status_is(accessor(UINT32_MAX, reinterpret_cast<char *>(buffer),
                     COPY_BUFFER_SIZE, required), COPY_UNKNOWN_ID);
  require(*required == 0, "unknown ID did not clear required size");
  unchanged(buffer, COPY_BUFFER_SIZE);
  status_is(accessor(id, nullptr, length, required), COPY_INVALID_ARGUMENT);
  require(*required == length, "invalid destination lost known size");
  status_is(accessor(id, reinterpret_cast<char *>(buffer), COPY_BUFFER_SIZE,
                     nullptr), COPY_INVALID_ARGUMENT);
  unchanged(buffer, COPY_BUFFER_SIZE);
}

static void semantic_case(copy_accessor accessor, unsigned variant, unsigned id,
                          unsigned char *copy, byte_reader reader) {
  const char *text = expected[variant][id - 1];
  size_t length = std::strlen(text) + 1;
  unsigned char buffer[COPY_BUFFER_SIZE];
  size_t required = SIZE_MAX;
  std::memset(buffer, 0xa6, sizeof(buffer));
  status_is(accessor(id, nullptr, 0, &required), COPY_NEED_CAPACITY);
  require(required == length, "required size must include exactly one NUL");
  status_is(accessor(id, reinterpret_cast<char *>(buffer) + 7, 0, &required),
            COPY_NEED_CAPACITY);
  unchanged(buffer, sizeof(buffer));
  status_is(accessor(id, reinterpret_cast<char *>(buffer) + 7, length - 1,
                     &required), COPY_NEED_CAPACITY);
  require(required == length, "short capacity changed required size");
  unchanged(buffer, sizeof(buffer));
  status_is(accessor(id, nullptr, 1, &required), COPY_INVALID_ARGUMENT);
  require(required == length, "null destination changed required size");
  status_is(accessor(id, reinterpret_cast<char *>(buffer) + 7, length, nullptr),
            COPY_INVALID_ARGUMENT);
  unchanged(buffer, sizeof(buffer));
  status_is(accessor(id, reinterpret_cast<char *>(buffer) + 7, length, &required),
            COPY_OK);
  require(required == length && std::memcmp(buffer + 7, text, length) == 0,
          "exact capacity did not copy exact bytes and NUL");
  unchanged(buffer, 7);
  unchanged(buffer + 7 + length, sizeof(buffer) - 7 - length);
  std::memcpy(copy, buffer + 7, length);
  consume(reader, copy, length, 17 + variant * 29 + id);
  std::memset(buffer, 0xa6, sizeof(buffer));
  status_is(accessor(id, reinterpret_cast<char *>(buffer) + 7,
                     sizeof(buffer) - 14, &required), COPY_OK);
  require(required == length && std::memcmp(buffer + 7, text, length) == 0,
          "repeated large-capacity copy changed exact bytes");
  unchanged(buffer, 7);
  unchanged(buffer + 7 + length, sizeof(buffer) - 7 - length);
}

static void semantics(const wchar_t *first, const wchar_t *second,
                      const wchar_t *consumer, const wchar_t *incompatible) {
  Image readers = load_image(consumer);
  byte_reader reader = reinterpret_cast<byte_reader>(
      owned_symbol(readers, "exchange_read_bytes"));
  Image producers[2] = {load_image(first), load_image(second)};
  copy_accessor accessors[2];
  for (unsigned variant = 0; variant < 2; ++variant)
    accessors[variant] = reinterpret_cast<copy_accessor>(
        owned_symbol(producers[variant], "exchange_copy_v1"));
  require(producers[0].handle != producers[1].handle &&
              accessors[0] != accessors[1],
          "independent producers share a handle or implementation");
  unsigned char copies[2][3][COPY_BUFFER_SIZE]{};
  for (unsigned id = 1; id <= 3; ++id)
    for (unsigned variant = 0; variant < 2; ++variant)
      semantic_case(accessors[variant], variant, id, copies[variant][id - 1], reader);
  unsigned char sentinel[COPY_BUFFER_SIZE];
  std::memset(sentinel, 0xa6, sizeof(sentinel));
  size_t required = SIZE_MAX;
  require(checked_copy(producers[0], accessors[1], 1,
                       reinterpret_cast<char *>(sentinel), sizeof(sentinel),
                       &required) == -1, "wrong-owner transfer did not reject");
  require(required == SIZE_MAX, "wrong-owner rejection wrote metadata");
  unchanged(sentinel, sizeof(sentinel));
  for (unsigned variant = 0; variant < 2; ++variant) {
    rejected_calls(accessors[variant], variant, 1, sentinel, &required);
    status_is(accessors[variant](0, nullptr, 0, &required), COPY_UNKNOWN_ID);
    require(required == 0, "unknown query did not clear required size");
    status_is(accessors[variant](0, reinterpret_cast<char *>(sentinel),
                                sizeof(sentinel), nullptr), COPY_INVALID_ARGUMENT);
    unchanged(sentinel, sizeof(sentinel));
  }
  Image v2 = load_image(incompatible);
  owned_symbol(v2, "exchange_copy_v2");
  copy_accessor missing = reinterpret_cast<copy_accessor>(
      GetProcAddress(v2.handle, "exchange_copy_v1"));
  require(missing == nullptr, "incompatible producer unexpectedly provides V1");
  required = SIZE_MAX;
  require(checked_copy(v2, missing, 1, reinterpret_cast<char *>(sentinel),
                       sizeof(sentinel), &required) == -1,
          "missing V1 resolution did not reject before transfer");
  require(required == SIZE_MAX, "incompatible version rejection wrote metadata");
  unchanged(sentinel, sizeof(sentinel));
  unload_image(v2);
  uint64_t digest = consume(reader, nullptr, 0, 101);
  for (unsigned variant = 0; variant < 2; ++variant) {
    accessors[variant] = nullptr;
    unload_image(producers[variant]);
    if (variant == 0) {
      require(GetModuleHandleW(producers[1].path.c_str()) == producers[1].handle,
              "unload removed the independent other producer");
      unsigned char probe[COPY_BUFFER_SIZE];
      status_is(accessors[1](1, reinterpret_cast<char *>(probe), sizeof(probe),
                             &required), COPY_OK);
      require(required == std::strlen(expected[1][0]) + 1 &&
                  std::memcmp(probe, expected[1][0], required) == 0,
              "live producer changed after other producer unloaded");
    }
    for (unsigned owner = 0; owner <= variant; ++owner)
      for (unsigned id = 1; id <= 3; ++id) {
        size_t length = std::strlen(expected[owner][id - 1]) + 1;
        require(std::memcmp(copies[owner][id - 1], expected[owner][id - 1],
                            length) == 0,
                "caller-owned copy changed after real producer unload");
        digest += consume(reader, copies[owner][id - 1], length,
                          71 + owner * 43 + id);
      }
  }
  reader = nullptr;
  unload_image(readers);
  std::printf("{\"ok\":true,\"kind\":\"semantics\",\"checks\":%u,"
              "\"statuses\":[%u,%u,%u,%u],\"reads\":%u,\"digest\":%llu,"
              "\"unmapped\":[true,true],\"missing_v1\":true,"
              "\"incompatible_destination_unchanged\":true,"
              "\"mismatched_owner_rejected\":true,\"no_owner_reference\":true,"
              "\"required_sizes\":[[%zu,%zu,1],[%zu,%zu,1]]}\n",
              checks, statuses[0], statuses[1], statuses[2], statuses[3], reads,
              static_cast<unsigned long long>(digest),
              std::strlen(expected[0][0]) + 1, std::strlen(expected[0][1]) + 1,
              std::strlen(expected[1][0]) + 1, std::strlen(expected[1][1]) + 1);
}

struct SharedObservation {
  unsigned char destination[COPY_BUFFER_SIZE];
  uint64_t effect;
  size_t required;
  volatile LONG stage;
  unsigned errors;
};

static uint64_t number(const wchar_t *text) {
  wchar_t *end = nullptr;
  errno = 0;
  unsigned long long value = std::wcstoull(text, &end, 0);
  require(errno == 0 && end != text && *end == 0, "invalid numeric argument");
  return value;
}

static constexpr unsigned concurrent_workers = 24;
static constexpr unsigned warm_copies = 12;
static constexpr DWORD concurrent_timeout = 10000;

struct CopyBundle {
  const unsigned char *cache;
  const volatile uint64_t *state;
  uint64_t cold_status;
};

struct Admission {
  CRITICAL_SECTION mutex;
  bool open = true;
  unsigned admitted = 0, completed = 0, outstanding = 0, rejected = 0;

  bool enter() {
    EnterCriticalSection(&mutex);
    bool accepted = open;
    if (accepted) {
      ++admitted;
      ++outstanding;
    } else
      ++rejected;
    LeaveCriticalSection(&mutex);
    return accepted;
  }

  void complete() {
    EnterCriticalSection(&mutex);
    ++completed;
    --outstanding;
    LeaveCriticalSection(&mutex);
  }
};

struct ConcurrentGroup {
  Admission admission;
  HANDLE start, ready, parked, drain;
  volatile LONG ready_count = 0, parked_count = 0;
};

struct CopyWorker {
  ConcurrentGroup *group;
  copy_accessor accessor;
  byte_reader reader;
  unsigned variant, id, index;
  unsigned char saved[2][COPY_BUFFER_SIZE];
  uint64_t effect = UINT64_C(0xdecafbad);
  unsigned checks = 0, statuses[4]{}, reads = 0;
  unsigned module_calls = 0, completed_calls = 0;
  bool pointers_cleared = false, post_close_rejected = false;
};

static void wait_event(HANDLE event, const char *message) {
  require(WaitForSingleObject(event, concurrent_timeout) == WAIT_OBJECT_0,
          message);
}

static int admitted_copy(CopyWorker &worker, uint32_t id, char *destination,
                         size_t capacity, size_t *required) {
  require(worker.group->admission.enter(), "open host rejected worker admission");
  ++worker.module_calls;
  int status = worker.accessor(id, destination, capacity, required);
  ++worker.completed_calls;
  worker.group->admission.complete();
  return status;
}

static void concurrent_success(CopyWorker &worker, unsigned slot,
                               bool already_admitted = false) {
  const char *text = expected[worker.variant][worker.id - 1];
  const size_t length = std::strlen(text) + 1;
  unsigned char destination[COPY_BUFFER_SIZE];
  std::memset(destination, 0xa6, sizeof(destination));
  size_t required = SIZE_MAX;
  int status;
  if (already_admitted) {
    ++worker.module_calls;
    status = worker.accessor(worker.id,
                             reinterpret_cast<char *>(destination) + 7,
                             length, &required);
    ++worker.completed_calls;
    worker.group->admission.complete();
  } else
    status = admitted_copy(worker, worker.id,
                           reinterpret_cast<char *>(destination) + 7,
                           length, &required);
  status_is(status, COPY_OK);
  require(required == length && std::memcmp(destination + 7, text, length) == 0,
          "concurrent copy changed exact string, NUL, or required size");
  unchanged(destination, 7);
  unchanged(destination + 7 + length, sizeof(destination) - 7 - length);
  if (slot < 2)
    std::memcpy(worker.saved[slot], destination + 7, length);
  consume(worker.reader, destination + 7, length,
          211 + worker.index * 17 + slot, &worker.effect);
}

static void concurrent_rejections(CopyWorker &worker) {
  unsigned char destination[COPY_BUFFER_SIZE];
  std::memset(destination, 0xa6, sizeof(destination));
  worker.effect = UINT64_C(0xdecafbad);
  const size_t length =
      std::strlen(expected[worker.variant][worker.id - 1]) + 1;
  size_t required = SIZE_MAX;
  status_is(admitted_copy(worker, worker.id, nullptr, 0, &required),
            COPY_NEED_CAPACITY);
  require(required == length, "concurrent query lost NUL-inclusive size");
  unchanged(destination, sizeof(destination));
  require(worker.effect == UINT64_C(0xdecafbad),
          "concurrent query changed worker effect sentinel");
  required = SIZE_MAX;
  status_is(admitted_copy(worker, worker.id,
                          reinterpret_cast<char *>(destination) + 7,
                          length - 1, &required), COPY_NEED_CAPACITY);
  require(required == length, "concurrent short capacity lost required size");
  unchanged(destination, sizeof(destination));
  require(worker.effect == UINT64_C(0xdecafbad),
          "concurrent short capacity changed worker effect sentinel");
  required = SIZE_MAX;
  status_is(admitted_copy(worker, UINT32_MAX,
                          reinterpret_cast<char *>(destination) + 7,
                          length, &required), COPY_UNKNOWN_ID);
  require(required == 0, "concurrent unknown ID did not clear required size");
  unchanged(destination, sizeof(destination));
  require(worker.effect == UINT64_C(0xdecafbad),
          "concurrent unknown ID changed worker effect sentinel");
  required = SIZE_MAX;
  status_is(admitted_copy(worker, worker.id, nullptr, length, &required),
            COPY_INVALID_ARGUMENT);
  require(required == length, "concurrent null destination lost known size");
  unchanged(destination, sizeof(destination));
  require(worker.effect == UINT64_C(0xdecafbad),
          "concurrent null destination changed worker effect sentinel");
  status_is(admitted_copy(worker, worker.id,
                          reinterpret_cast<char *>(destination) + 7, length,
                          nullptr), COPY_INVALID_ARGUMENT);
  unchanged(destination, sizeof(destination));
  require(worker.effect == UINT64_C(0xdecafbad),
          "concurrent null required pointer changed worker effect sentinel");
}

static DWORD WINAPI copy_worker(void *argument) {
  auto &worker = *static_cast<CopyWorker *>(argument);
  if (InterlockedIncrement(&worker.group->ready_count) == concurrent_workers)
    require(SetEvent(worker.group->ready) != 0, "signaling ready worker barrier");
  wait_event(worker.group->start, "timed out at cold worker barrier");
  // Half the workers start with an eligible copy; the others mix all ordinary
  // errors into the cold burst. A barrier does not prove decoder overlap.
  if (worker.index & 1)
    concurrent_rejections(worker);
  concurrent_success(worker, 0);
  for (unsigned repeat = 0; repeat < warm_copies; ++repeat) {
    concurrent_rejections(worker);
    concurrent_success(worker, 2 + repeat);
  }
  // Reserve one final application call while admission is open. This worker
  // parks in the host, not inside the producer or a loader-controlled callback.
  require(worker.group->admission.enter(), "reserving final drain copy");
  if (InterlockedIncrement(&worker.group->parked_count) == concurrent_workers)
    require(SetEvent(worker.group->parked) != 0, "signaling reserved drain work");
  wait_event(worker.group->drain, "timed out waiting for host admission close");
  require(!worker.group->admission.enter(),
          "closed host admitted a worker without producer lifetime ownership");
  worker.post_close_rejected = true;
  concurrent_success(worker, 1, true);
  worker.accessor = nullptr;
  worker.reader = nullptr;
  worker.pointers_cleared = true;
  worker.checks = checks;
  worker.reads = reads;
  for (unsigned status = 0; status < 4; ++status)
    worker.statuses[status] = statuses[status];
  return 0;
}

static void inspect_bundle(const CopyBundle &bundle, unsigned variant,
                           unsigned id, bool lazy, bool touched) {
  size_t length = std::strlen(expected[variant][id - 1]) + 1;
  if (lazy && !touched) {
    require(bundle.state[1] == bundle.cold_status &&
                bundle.state[2] == bundle.cold_status,
            "untouched lazy source lost its cold authentication state");
    for (size_t offset = 0; offset < length; ++offset)
      require(bundle.cache[offset] == 0, "cold lazy cache contains plaintext");
  } else {
    require(std::memcmp(bundle.cache, expected[variant][id - 1], length) == 0,
            "authenticated cache differs after constructor or joined copies");
    if (lazy && touched)
      require(bundle.state[1] != bundle.cold_status && bundle.state[2] != 0,
              "joined copies did not complete lazy source authentication");
  }
}

static void concurrency(wchar_t **argv) {
  // host concurrent A B consumer strategy scenario [cache state cold] x 6.
  Image consumer = load_image(argv[4]);
  byte_reader reader = reinterpret_cast<byte_reader>(
      owned_symbol(consumer, "exchange_read_bytes"));
  Image producers[2] = {load_image(argv[2]), load_image(argv[3])};
  copy_accessor accessors[2];
  for (unsigned variant = 0; variant < 2; ++variant)
    accessors[variant] = reinterpret_cast<copy_accessor>(
        owned_symbol(producers[variant], "exchange_copy_v1"));
  require(producers[0].handle != producers[1].handle &&
              accessors[0] != accessors[1],
          "concurrent independent producers alias their mapping or accessor");
  const bool raw = std::wcscmp(argv[5], L"raw") == 0;
  const bool lazy = std::wcscmp(argv[5], L"lazy") == 0;
  require(raw || lazy || std::wcscmp(argv[5], L"ctor") == 0,
          "invalid concurrent producer strategy");
  CopyBundle bundles[2][3]{};
  if (!raw)
    for (unsigned variant = 0; variant < 2; ++variant)
      for (unsigned source = 0; source < 3; ++source) {
        unsigned offset = 7 + (variant * 3 + source) * 3;
        auto base = reinterpret_cast<const unsigned char *>(producers[variant].handle);
        bundles[variant][source] = {
            base + static_cast<uintptr_t>(number(argv[offset])),
            reinterpret_cast<const volatile uint64_t *>(
                base + static_cast<uintptr_t>(number(argv[offset + 1]))),
            number(argv[offset + 2])};
        inspect_bundle(bundles[variant][source], variant, source + 1, lazy, false);
      }
  unsigned same_id = 0;
  for (unsigned id = 1; id <= 3; ++id) {
    wchar_t name[] = L"same-1";
    name[5] = static_cast<wchar_t>(L'0' + id);
    if (std::wcscmp(argv[6], name) == 0)
      same_id = id;
  }
  bool independent_sources = std::wcscmp(argv[6], L"independent-sources") == 0;
  bool independent_producers =
      std::wcscmp(argv[6], L"independent-producers") == 0;
  require(same_id || independent_sources || independent_producers,
          "invalid concurrent scenario");
  ConcurrentGroup group{};
  InitializeCriticalSection(&group.admission.mutex);
  group.start = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  group.ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  group.parked = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  group.drain = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  require(group.start && group.ready && group.parked && group.drain,
          "creating bounded host thread barriers");
  CopyWorker workers[concurrent_workers]{};
  HANDLE threads[concurrent_workers]{};
  bool touched[2][3]{};
  for (unsigned index = 0; index < concurrent_workers; ++index) {
    auto &worker = workers[index];
    worker.group = &group;
    worker.index = index;
    // Adjacent success-first/error-first workers target the same cold source.
    worker.variant = (same_id || independent_producers) ? (index / 2) % 2 : 0;
    worker.id = same_id ? same_id :
                (independent_producers ? (index / 4) % 3 : (index / 2) % 3) + 1;
    worker.accessor = accessors[worker.variant];
    worker.reader = reader;
    std::memset(worker.saved, 0xa6, sizeof(worker.saved));
    touched[worker.variant][worker.id - 1] = true;
    threads[index] = CreateThread(nullptr, 0, copy_worker, &worker, 0, nullptr);
    require(threads[index] != nullptr, "creating native copy worker");
  }
  wait_event(group.ready, "timed out assembling simultaneous cold callers");
  require(SetEvent(group.start) != 0, "releasing simultaneous cold callers");
  wait_event(group.parked, "timed out reserving host-owned drain work");
  EnterCriticalSection(&group.admission.mutex);
  require(group.admission.open &&
              group.admission.outstanding == concurrent_workers,
          "admission close did not own outstanding reserved work");
  group.admission.open = false;
  unsigned outstanding_at_close = group.admission.outstanding;
  LeaveCriticalSection(&group.admission.mutex);
  require(!group.admission.enter(), "closed host admitted an owner module call");
  require(SetEvent(group.drain) != 0, "releasing reserved calls for drain");
  require(WaitForMultipleObjects(concurrent_workers, threads, TRUE,
                                 concurrent_timeout) == WAIT_OBJECT_0,
          "timed out draining and joining native workers");
  unsigned module_calls = 0, completed_calls = 0;
  for (unsigned index = 0; index < concurrent_workers; ++index) {
    auto &worker = workers[index];
    DWORD code = 1;
    require(GetExitCodeThread(threads[index], &code) != 0 && code == 0,
            "native copy worker failed");
    require(CloseHandle(threads[index]) != 0, "closing joined worker handle");
    require(worker.pointers_cleared && worker.accessor == nullptr &&
                worker.reader == nullptr && worker.post_close_rejected,
            "worker retained callable pointers or admitted work after close");
    checks += worker.checks;
    reads += worker.reads;
    for (unsigned status = 0; status < 4; ++status)
      statuses[status] += worker.statuses[status];
    module_calls += worker.module_calls;
    completed_calls += worker.completed_calls;
  }
  require(group.admission.outstanding == 0 &&
              group.admission.admitted == group.admission.completed &&
              group.admission.admitted == module_calls &&
              completed_calls == module_calls &&
              group.admission.rejected == concurrent_workers + 1,
          "host admission/drain module-call accounting differs");
  if (!raw)
    for (unsigned variant = 0; variant < 2; ++variant)
      for (unsigned source = 0; source < 3; ++source)
        inspect_bundle(bundles[variant][source], variant, source + 1, lazy,
                       touched[variant][source]);
  accessors[0] = accessors[1] = nullptr;
  require(accessors[0] == nullptr && accessors[1] == nullptr,
          "owner retained producer callable pointers");
  // No producer callable survives join. Clear private producer observations
  // before unload as well; only caller-owned bytes and the consumer stay live.
  std::memset(bundles, 0, sizeof(bundles));
  unload_image(producers[0]);
  unload_image(producers[1]);
  require(GetModuleHandleW(consumer.path.c_str()) == consumer.handle,
          "consumer mapping did not outlive producer drain/unload");
  uint64_t digest = 0;
  for (unsigned index = 0; index < concurrent_workers; ++index) {
    auto &worker = workers[index];
    size_t length = std::strlen(expected[worker.variant][worker.id - 1]) + 1;
    for (unsigned slot = 0; slot < 2; ++slot) {
      require(std::memcmp(worker.saved[slot],
                          expected[worker.variant][worker.id - 1], length) == 0,
              "worker-owned copy changed after actual producer unmapping");
      unchanged(worker.saved[slot] + length, COPY_BUFFER_SIZE - length);
      digest += consume(reader, worker.saved[slot], length,
                        701 + index * 13 + slot, &worker.effect);
    }
  }
  HANDLE events[] = {group.start, group.ready, group.parked, group.drain};
  for (HANDLE event : events)
    require(CloseHandle(event) != 0, "closing host barrier event handle");
  DeleteCriticalSection(&group.admission.mutex);
  reader = nullptr;
  unload_image(consumer);
  std::printf("{\"ok\":true,\"kind\":\"concurrency\",\"scenario\":\"%ls\","
              "\"strategy\":\"%ls\",\"workers\":%u,\"warm_rounds\":%u,"
              "\"checks\":%u,\"statuses\":[%u,%u,%u,%u],\"reads\":%u,"
              "\"admitted\":%u,\"completed\":%u,\"module_calls\":%u,"
              "\"post_close_rejected\":%u,\"outstanding_at_close\":%u,"
              "\"close_phase\":\"host-reserved-not-inside-producer\","
              "\"host_parked_at_close\":true,\"drained\":true,"
              "\"barrier_started\":true,\"decoder_overlap_proven\":false,"
              "\"loader_lock_contention_claimed\":false,"
              "\"cold_state_checked\":%s,\"cold_bundles_checked\":%u,"
              "\"post_join_bundles_checked\":%u,\"callables_cleared\":true,"
              "\"unmapped\":[true,true],\"virtual_query_removed\":[true,true],"
              "\"copies_after_unload\":%u,"
              "\"no_owner_reference\":true,\"digest\":%llu}\n",
              argv[6], argv[5], concurrent_workers, warm_copies, checks,
              statuses[0], statuses[1], statuses[2], statuses[3], reads,
              group.admission.admitted, group.admission.completed, module_calls,
              group.admission.rejected, outstanding_at_close,
              lazy ? "true" : "false", lazy ? 6 : 0, raw ? 0 : 6,
              concurrent_workers * 2, static_cast<unsigned long long>(digest));
}

static void mutate_data(const Image &image, uintptr_t rva, unsigned original) {
  uintptr_t base = reinterpret_cast<uintptr_t>(image.handle);
  uintptr_t address = base + rva;
  require(address >= base, "mutation address overflow");
  MEMORY_BASIC_INFORMATION memory{};
  require(VirtualQuery(reinterpret_cast<const void *>(address), &memory,
                       sizeof(memory)) == sizeof(memory), "querying mutation data");
  require(memory.AllocationBase == image.handle && memory.Type == MEM_IMAGE &&
              memory.State == MEM_COMMIT && !(memory.Protect & 0xf0) &&
              !(memory.Protect & (PAGE_NOACCESS | PAGE_GUARD)),
          "mutation target is not bounded nonexecutable producer data");
  DWORD protection = 0;
  auto target = reinterpret_cast<volatile unsigned char *>(address);
  require(VirtualProtect(reinterpret_cast<void *>(address), 1, PAGE_READWRITE,
                         &protection) != 0, "making producer data writable");
  require(*target == original, "mutation byte differs from PE data or warm cache");
  *target ^= 1;
  require(*target == (original ^ 1), "data-only mutation did not take effect");
  DWORD replaced = 0;
  require(VirtualProtect(reinterpret_cast<void *>(address), 1, protection,
                         &replaced) != 0, "restoring producer data protection");
}

static std::wstring quote(const wchar_t *text) {
  std::wstring result = L"\"";
  unsigned slashes = 0;
  for (; *text; ++text) {
    if (*text == L'\\') {
      ++slashes;
      continue;
    }
    result.append(*text == L'\"' ? slashes * 2 + 1 : slashes, L'\\');
    slashes = 0;
    result += *text;
  }
  result.append(slashes * 2, L'\\');
  return result + L"\"";
}

static void tamper_child(wchar_t **argv) {
  // argv: host tamper-child producer consumer variant id mode warm rva byte
  //       strategy cache-rva state-rva cold-status shared-map.
  HANDLE mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, argv[14]);
  require(mapping != nullptr, "opening parent shared observation");
  auto shared = static_cast<SharedObservation *>(MapViewOfFile(
      mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedObservation)));
  require(shared != nullptr, "mapping parent shared observation");
  unsigned variant = static_cast<unsigned>(number(argv[4])) - 1;
  unsigned id = static_cast<unsigned>(number(argv[5]));
  bool warm = number(argv[7]) != 0;
  unsigned original = static_cast<unsigned>(number(argv[9]));
  require(variant < 2 && id >= 1 && id <= 3 && original <= 255,
          "invalid tamper arguments");
  Image readers = load_image(argv[3]);
  byte_reader reader = reinterpret_cast<byte_reader>(
      owned_symbol(readers, "exchange_read_bytes"));
  Image source = load_image(argv[2]);
  copy_accessor accessor = reinterpret_cast<copy_accessor>(
      owned_symbol(source, "exchange_copy_v1"));
  size_t length = std::strlen(expected[variant][id - 1]) + 1;
  const auto cache = reinterpret_cast<const unsigned char *>(source.handle) +
                     static_cast<uintptr_t>(number(argv[11]));
  const auto state = reinterpret_cast<const volatile uint64_t *>(
      reinterpret_cast<const unsigned char *>(source.handle) +
      static_cast<uintptr_t>(number(argv[12])));
  const uint64_t cold_status = static_cast<uint64_t>(number(argv[13]));
  const bool lazy = std::wcscmp(argv[10], L"lazy") == 0;
  if (std::wcscmp(argv[10], L"ctor") == 0)
    require(std::memcmp(cache, expected[variant][id - 1], length) == 0,
            "CRT constructor did not authenticate and decode before first copy");
  else {
    require(std::wcscmp(argv[10], L"lazy") == 0, "invalid decode strategy");
    require(state[1] == cold_status && state[2] == cold_status,
            "lazy source state completed before first copy");
    for (size_t index = 0; index < length; ++index)
      require(cache[index] == 0, "lazy source decoded before first copy");
  }
  if (warm) {
    unsigned char first[COPY_BUFFER_SIZE];
    size_t required;
    status_is(accessor(id, reinterpret_cast<char *>(first), sizeof(first),
                       &required), COPY_OK);
    require(required == length &&
                std::memcmp(first, expected[variant][id - 1], length) == 0,
            "warmup copy invalid before data corruption");
    consume(reader, first, length, 89 + variant);
  }
  InterlockedExchange(&shared->stage, 1);
  mutate_data(source, static_cast<uintptr_t>(number(argv[8])), original);
  InterlockedExchange(&shared->stage, 2);
  rejected_calls(accessor, variant, id, shared->destination, &shared->required);
  shared->errors = 5;
  if (lazy && !warm)
    require(state[1] == cold_status && state[2] == cold_status,
            "ordinary rejection changed cold authentication state");
  InterlockedExchange(&shared->stage, 3);
  int status = accessor(id, reinterpret_cast<char *>(shared->destination) + 7,
                        length, &shared->required);
  InterlockedExchange(&shared->stage, 4);
  if (status == COPY_OK)
    shared->effect = reader(shared->destination + 7, length, 97, &shared->effect);
  ExitProcess(90);
}

static void tamper(wchar_t **argv) {
  wchar_t name[128];
  std::swprintf(name, 128, L"Local\\ObfCrossDllCopy-%lu-%llu",
                static_cast<unsigned long>(GetCurrentProcessId()),
                static_cast<unsigned long long>(GetTickCount64()));
  HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr,
                                      PAGE_READWRITE, 0,
                                      sizeof(SharedObservation), name);
  require(mapping != nullptr && GetLastError() != ERROR_ALREADY_EXISTS,
          "creating fresh shared observation");
  auto shared = static_cast<SharedObservation *>(MapViewOfFile(
      mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedObservation)));
  require(shared != nullptr, "mapping shared observation");
  std::memset(shared, 0, sizeof(*shared));
  std::memset(shared->destination, 0xa6, sizeof(shared->destination));
  shared->effect = UINT64_C(0xdecafbad);
  shared->required = SIZE_MAX;
  wchar_t executable[32768];
  DWORD size = GetModuleFileNameW(nullptr, executable, 32768);
  require(size > 0 && size < 32768, "resolving host executable");
  std::wstring command = quote(executable) + L" tamper-child";
  for (unsigned index = 2; index < 14; ++index)
    command += L" " + quote(argv[index]);
  command += L" " + quote(name);
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  require(CreateProcessW(executable, command.data(), nullptr, nullptr, FALSE,
                         CREATE_NO_WINDOW, nullptr, nullptr, &startup,
                         &process) != 0, "starting native tamper child");
  DWORD waited = WaitForSingleObject(process.hProcess, 25000);
  if (waited != WAIT_OBJECT_0)
    TerminateProcess(process.hProcess, 91);
  require(waited == WAIT_OBJECT_0, "native tamper child timed out");
  DWORD code = 0;
  require(GetExitCodeProcess(process.hProcess, &code) != 0 && code == 0xc000001dUL,
          "authentication did not terminate with STATUS_ILLEGAL_INSTRUCTION");
  MemoryBarrier();
  require(shared->stage == 3 && shared->errors == 5,
          "query/error certified corrupted data, or successful copy returned");
  unchanged(shared->destination, sizeof(shared->destination));
  require(shared->effect == UINT64_C(0xdecafbad),
          "consumer effect changed after authentication rejection");
  unsigned variant = static_cast<unsigned>(number(argv[4]));
  unsigned id = static_cast<unsigned>(number(argv[5]));
  require(variant >= 1 && variant <= 2 && id >= 1 && id <= 3,
          "invalid parent tamper arguments");
  require(shared->required == std::strlen(expected[variant - 1][id - 1]) + 1,
          "copy lost known required size before authentication");
  std::printf("{\"ok\":true,\"kind\":\"tamper\",\"mode\":\"%ls\","
              "\"warm\":%s,\"variant\":%u,\"id\":%u,\"exception_code\":%lu,"
              "\"stage\":%ld,\"ordinary_rejections\":%u,"
              "\"destination_unchanged\":true,\"effect_unchanged\":true,"
              "\"required\":%zu,\"lazy_state_checked\":%s}\n",
              argv[6], number(argv[7]) ? "true" : "false",
              variant, id, static_cast<unsigned long>(code), shared->stage,
              shared->errors, shared->required,
              std::wcscmp(argv[10], L"lazy") == 0 ? "true" : "false");
  require(CloseHandle(process.hThread) != 0 && CloseHandle(process.hProcess) != 0,
          "closing child process handles");
  require(UnmapViewOfFile(shared) != 0 && CloseHandle(mapping) != 0,
          "releasing shared observation");
}

int wmain(int argc, wchar_t **argv) {
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
               SEM_NOOPENFILEERRORBOX);
  if (argc == 6 && std::wcscmp(argv[1], L"semantics") == 0)
    semantics(argv[2], argv[3], argv[4], argv[5]);
  else if ((argc == 7 || argc == 25) &&
           std::wcscmp(argv[1], L"concurrent") == 0 &&
           ((argc == 7 && std::wcscmp(argv[5], L"raw") == 0) ||
            (argc == 25 && std::wcscmp(argv[5], L"raw") != 0)))
    concurrency(argv);
  else if (argc == 14 && std::wcscmp(argv[1], L"tamper") == 0)
    tamper(argv);
  else if (argc == 15 && std::wcscmp(argv[1], L"tamper-child") == 0)
    tamper_child(argv);
  else {
    std::fprintf(stderr, "usage: host semantics A.dll B.dll consumer.dll v2.dll\n"
                        "       host tamper producer consumer variant id mode warm rva byte strategy cache-rva state-rva cold-status\n"
                        "       host concurrent A B consumer raw scenario\n"
                        "       host concurrent A B consumer lazy|ctor scenario [cache-rva state-rva cold-status]x6\n");
    return 2;
  }
  return 0;
}
