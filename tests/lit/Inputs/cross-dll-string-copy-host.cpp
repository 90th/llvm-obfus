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
static unsigned checks, statuses[4], reads;

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
                        size_t count, uint64_t salt) {
  uint64_t weighted = 0;
  for (size_t index = 0; index < count; ++index)
    weighted += static_cast<uint64_t>(bytes[index]) * (index + 1);
  uint64_t oracle = (UINT64_C(0x13579bdf) ^ salt) + weighted +
                    salt * count * (static_cast<uint64_t>(count) + 1) / 2;
  uint64_t effect = UINT64_C(0xdecafbad);
  uint64_t actual = reader(bytes, count, salt, &effect);
  require(actual == oracle, "consumer returned incorrect byte arithmetic");
  require(effect == (oracle ^ (salt << 1)), "consumer wrote incorrect effect");
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
  //       strategy cache-rva shared-map. No application copy runs in DllMain.
  HANDLE mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, argv[12]);
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
  if (std::wcscmp(argv[10], L"ctor") == 0)
    require(std::memcmp(cache, expected[variant][id - 1], length) == 0,
            "CRT constructor did not authenticate and decode before first copy");
  else {
    require(std::wcscmp(argv[10], L"lazy") == 0, "invalid decode strategy");
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
  for (unsigned index = 2; index < 12; ++index)
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
              "\"required\":%zu}\n", argv[6], number(argv[7]) ? "true" : "false",
              variant, id, static_cast<unsigned long>(code), shared->stage,
              shared->errors, shared->required);
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
  else if (argc == 12 && std::wcscmp(argv[1], L"tamper") == 0)
    tamper(argv);
  else if (argc == 13 && std::wcscmp(argv[1], L"tamper-child") == 0)
    tamper_child(argv);
  else {
    std::fprintf(stderr, "usage: host semantics A.dll B.dll consumer.dll v2.dll\n"
                        "       host tamper producer consumer variant id mode warm rva byte strategy cache-rva\n");
    return 2;
  }
  return 0;
}
