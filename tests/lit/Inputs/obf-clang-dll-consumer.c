#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define THREAD_COUNT 4
#define CALL_COUNT 8
#define LOAD_COUNT 4

typedef uint64_t (*calculation_fn)(uint64_t, uint64_t *);
typedef const char *(*text_fn)(void);
typedef uint64_t (*checksum_fn)(uint64_t);
typedef uint64_t (*init_fn)(void);

struct dll_api {
  calculation_fn vm;
  calculation_fn strong_vm;
  text_fn vm_text;
  text_fn strong_vm_text;
  checksum_fn checksum;
  init_fn init_value;
  text_fn init_text;
};

struct worker {
  const struct dll_api *api;
  HANDLE start;
  HANDLE ready;
  LONG *ready_count;
  unsigned index;
  unsigned errors;
  const char *vm_borrowed;
  const char *strong_borrowed;
};

static uint64_t expected_vm(uint64_t value) {
  const uint64_t table[4] = {0x11223344ULL, 0x55667788ULL, 0x99aabbccULL, 0xddeeff11ULL};
  const unsigned char text[4] = {100, 108, 108, 45};
  return value * 7ULL + table[value & 3ULL] + text[value & 3ULL];
}

static uint64_t expected_strong(uint64_t value) {
  const uint64_t table[4] = {0x10203040ULL, 0x50607080ULL, 0x90a0b0c0ULL, 0xd0e0f001ULL};
  const unsigned char text[4] = {100, 108, 108, 45};
  return value * 11ULL + table[value & 3ULL] + text[value & 3ULL];
}

static DWORD WINAPI call_worker(void *opaque) {
  struct worker *worker = (struct worker *)opaque;
  uint64_t vm_effect = 0;
  uint64_t strong_effect = 0;
  uint64_t vm_expected_effect = 0;
  uint64_t strong_expected_effect = 0;
  if (InterlockedIncrement(worker->ready_count) == THREAD_COUNT) {
    SetEvent(worker->ready);
  }
  if (WaitForSingleObject(worker->start, INFINITE) != WAIT_OBJECT_0) {
    worker->errors = 1;
    return 1;
  }
  for (unsigned call = 0; call < CALL_COUNT; ++call) {
    const uint64_t value = worker->index * CALL_COUNT + call;
    const uint64_t vm_result = expected_vm(value);
    const uint64_t strong_result = expected_strong(value);
    worker->errors += worker->api->vm(value, &vm_effect) != vm_result;
    worker->errors += worker->api->strong_vm(value, &strong_effect) != strong_result;
    vm_expected_effect += vm_result ^ 0x13579bdfULL;
    strong_expected_effect += strong_result ^ 0x2468ace0ULL;
    worker->errors += vm_effect != vm_expected_effect;
    worker->errors += strong_effect != strong_expected_effect;
    worker->vm_borrowed = worker->api->vm_text();
    worker->strong_borrowed = worker->api->strong_vm_text();
    worker->errors += strcmp(worker->vm_borrowed, "dll-vm-cold-authenticated") != 0;
    worker->errors += strcmp(worker->strong_borrowed, "dll-strong-vm-cold-authenticated") != 0;
    worker->errors += worker->api->checksum(value) != value + 3ULL;
  }
  return worker->errors != 0;
}

static int exercise(const struct dll_api *api) {
  HANDLE threads[THREAD_COUNT];
  struct worker workers[THREAD_COUNT] = {0};
  LONG ready_count = 0;
  HANDLE start = CreateEventA(NULL, TRUE, FALSE, NULL);
  HANDLE ready = CreateEventA(NULL, TRUE, FALSE, NULL);
  if (start == NULL || ready == NULL) {
    return 1;
  }
  if (api->init_value() != 0x123456789abcdef0ULL ||
      api->init_text() == NULL || strcmp(api->init_text(), "dll-initializer-authenticated") != 0) {
    return 1;
  }
  for (unsigned index = 0; index < THREAD_COUNT; ++index) {
    workers[index].api = api;
    workers[index].start = start;
    workers[index].ready = ready;
    workers[index].ready_count = &ready_count;
    workers[index].index = index;
    threads[index] = CreateThread(NULL, 0, call_worker, &workers[index], 0, NULL);
    if (threads[index] == NULL) {
      ExitProcess(20);
    }
  }
  if (WaitForSingleObject(ready, 60000) != WAIT_OBJECT_0 || !SetEvent(start) ||
      WaitForMultipleObjects(THREAD_COUNT, threads, TRUE, 60000) != WAIT_OBJECT_0) {
    /* Do not unload a module or return stack state while a caller is active. */
    ExitProcess(21);
  }
  unsigned errors = 0;
  for (unsigned index = 0; index < THREAD_COUNT; ++index) {
    DWORD result = 1;
    errors += !GetExitCodeThread(threads[index], &result) || result != 0;
    errors += workers[index].errors;
    errors += strcmp(workers[index].vm_borrowed, "dll-vm-cold-authenticated") != 0;
    errors += strcmp(workers[index].strong_borrowed, "dll-strong-vm-cold-authenticated") != 0;
    workers[index].vm_borrowed = NULL;
    workers[index].strong_borrowed = NULL;
    CloseHandle(threads[index]);
  }
  CloseHandle(start);
  CloseHandle(ready);
  return errors != 0;
}

#ifdef DLL_IMPORT_CONSUMER
__declspec(dllimport) uint64_t dll_vm(uint64_t, uint64_t *);
__declspec(dllimport) uint64_t dll_strong_vm(uint64_t, uint64_t *);
__declspec(dllimport) const char *dll_vm_text(void);
__declspec(dllimport) const char *dll_strong_vm_text(void);
__declspec(dllimport) uint64_t dll_checksum(uint64_t);
__declspec(dllimport) uint64_t dll_init_value(void);
__declspec(dllimport) const char *dll_init_text(void);

int main(void) {
  const struct dll_api api = {dll_vm, dll_strong_vm, dll_vm_text, dll_strong_vm_text,
                              dll_checksum, dll_init_value, dll_init_text};
  if (exercise(&api)) {
    return 1;
  }
  puts("DLL_IMPORT_OK vm=1 strong_vm=1 effects=1 init=1 concurrent=1");
  return 0;
}
#else
static const char *const export_names[7] = {
    "dll_vm", "dll_strong_vm", "dll_vm_text", "dll_strong_vm_text",
    "dll_checksum", "dll_init_value", "dll_init_text"};

static int check_exports(HMODULE module) {
  const unsigned char *base = (const unsigned char *)module;
  const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
  const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
  const IMAGE_DATA_DIRECTORY directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (directory.VirtualAddress == 0) {
    return 1;
  }
  const IMAGE_EXPORT_DIRECTORY *exports = (const IMAGE_EXPORT_DIRECTORY *)(base + directory.VirtualAddress);
  if (exports->NumberOfNames != 7 || exports->NumberOfFunctions != 7) {
    return 1;
  }
  const DWORD *names = (const DWORD *)(base + exports->AddressOfNames);
  const WORD *ordinals = (const WORD *)(base + exports->AddressOfNameOrdinals);
  const DWORD *functions = (const DWORD *)(base + exports->AddressOfFunctions);
  unsigned seen = 0;
  unsigned seen_ordinals = 0;
  for (unsigned index = 0; index < 7; ++index) {
    unsigned expected = 0;
    while (expected < 7 && strcmp((const char *)(base + names[index]), export_names[expected]) != 0) {
      ++expected;
    }
    if (expected == 7 || (seen & (1U << expected)) || ordinals[index] >= 7 ||
        (seen_ordinals & (1U << ordinals[index]))) {
      return 1;
    }
    seen |= 1U << expected;
    seen_ordinals |= 1U << ordinals[index];
    const DWORD target = functions[ordinals[index]];
    if (target == 0 || target >= nt->OptionalHeader.SizeOfImage ||
        (target >= directory.VirtualAddress && target - directory.VirtualAddress < directory.Size)) {
      return 1;
    }
  }
  return seen != 127 || seen_ordinals != 127;
}

static void *reserve_preferred_base(const char *path) {
  IMAGE_DOS_HEADER dos;
  IMAGE_NT_HEADERS64 nt;
  DWORD count;
  HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE) {
    return NULL;
  }
  int valid = ReadFile(file, &dos, sizeof(dos), &count, NULL) && count == sizeof(dos) &&
              dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew > 0;
  if (valid) {
    valid = SetFilePointer(file, dos.e_lfanew, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER &&
            ReadFile(file, &nt, sizeof(nt), &count, NULL) && count == sizeof(nt) &&
            nt.Signature == IMAGE_NT_SIGNATURE && nt.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
            (nt.FileHeader.Characteristics & IMAGE_FILE_DLL) != 0 &&
            nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  }
  CloseHandle(file);
  if (!valid || nt.OptionalHeader.ImageBase == 0 || nt.OptionalHeader.SizeOfImage == 0) {
    return NULL;
  }
  void *preferred = (void *)(uintptr_t)nt.OptionalHeader.ImageBase;
  void *reservation = VirtualAlloc(preferred, nt.OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_NOACCESS);
  if (reservation != preferred) {
    if (reservation != NULL) {
      VirtualFree(reservation, 0, MEM_RELEASE);
    }
    return NULL;
  }
  return reservation;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    return 1;
  }
  void *reservation = reserve_preferred_base(argv[1]);
  if (reservation == NULL) {
    fprintf(stderr, "preferred-base reservation failed: %lu\n", GetLastError());
    return 2;
  }
  for (unsigned cycle = 0; cycle < LOAD_COUNT; ++cycle) {
    HMODULE module = LoadLibraryA(argv[1]);
    if (module == NULL || (void *)module == reservation) {
      fprintf(stderr, "forced-rebase load failed: %lu\n", GetLastError());
      return 3;
    }
    if (check_exports(module)) {
      return 4;
    }
    struct dll_api api;
    api.vm = (calculation_fn)GetProcAddress(module, "dll_vm");
    api.strong_vm = (calculation_fn)GetProcAddress(module, "dll_strong_vm");
    api.vm_text = (text_fn)GetProcAddress(module, "dll_vm_text");
    api.strong_vm_text = (text_fn)GetProcAddress(module, "dll_strong_vm_text");
    api.checksum = (checksum_fn)GetProcAddress(module, "dll_checksum");
    api.init_value = (init_fn)GetProcAddress(module, "dll_init_value");
    api.init_text = (text_fn)GetProcAddress(module, "dll_init_text");
    if (api.vm == NULL || api.strong_vm == NULL || api.vm_text == NULL || api.strong_vm_text == NULL ||
        api.checksum == NULL || api.init_value == NULL || api.init_text == NULL ||
        exercise(&api)) {
      return 5;
    }
    memset(&api, 0, sizeof(api));
    if (!FreeLibrary(module)) {
      return 6;
    }
  }
  if (!VirtualFree(reservation, 0, MEM_RELEASE)) {
    return 7;
  }
  puts("DLL_DYNAMIC_OK vm=1 strong_vm=1 effects=1 init=1 concurrent=1 exports=7 rebased=1 joined_unloads=4");
  return 0;
}
#endif
