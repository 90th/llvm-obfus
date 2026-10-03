#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int fail(const char* message) {
  fprintf(stderr, "SELF_CHECKSUM_DLL_ERROR: %s (Windows error %lu)\n", message,
          (unsigned long)GetLastError());
  return 2;
}

static int range_is_occupied(uintptr_t begin, size_t size) {
  uintptr_t end = begin + size;
  while (begin < end) {
    MEMORY_BASIC_INFORMATION info;
    if (VirtualQuery((const void*)begin, &info, sizeof(info)) == 0) {
      return 0;
    }
    if (info.State != MEM_FREE) {
      return 1;
    }
    uintptr_t next = (uintptr_t)info.BaseAddress + info.RegionSize;
    if (next <= begin) {
      return 0;
    }
    begin = next;
  }
  return 0;
}

int main(int argc, char** argv) {
  if (argc != 2) {
    return fail("expected one DLL path");
  }
  FILE* file = fopen(argv[1], "rb");
  if (file == NULL) {
    return fail("cannot read DLL headers");
  }
  IMAGE_DOS_HEADER dos;
  IMAGE_NT_HEADERS64 headers;
  int valid = fread(&dos, sizeof(dos), 1, file) == 1 &&
              dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew >= 0 &&
              fseek(file, dos.e_lfanew, SEEK_SET) == 0 &&
              fread(&headers, sizeof(headers), 1, file) == 1;
  fclose(file);
  if (!valid || headers.Signature != IMAGE_NT_SIGNATURE ||
      headers.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
      (headers.FileHeader.Characteristics & IMAGE_FILE_DLL) == 0 ||
      headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
      headers.OptionalHeader.SizeOfImage == 0 ||
      headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0) {
    return fail("expected an AMD64 DLL with real loader fixups");
  }

  uintptr_t preferred = (uintptr_t)headers.OptionalHeader.ImageBase;
  size_t image_size = headers.OptionalHeader.SizeOfImage;
  void* reservation = VirtualAlloc((void*)preferred, image_size, MEM_RESERVE, PAGE_NOACCESS);
  if (reservation != NULL && (uintptr_t)reservation != preferred) {
    VirtualFree(reservation, 0, MEM_RELEASE);
    return fail("reservation did not cover the preferred base");
  }
  if (reservation == NULL && !range_is_occupied(preferred, image_size)) {
    return fail("cannot block the preferred image range");
  }

  HMODULE module = LoadLibraryA(argv[1]);
  int result = 2;
  if (module == NULL) {
    result = fail("LoadLibraryA failed");
    goto done;
  }
  if ((uintptr_t)module == preferred) {
    result = fail("DLL did not rebase");
    goto done;
  }

  const IMAGE_DOS_HEADER* loaded_dos = (const IMAGE_DOS_HEADER*)module;
  const IMAGE_NT_HEADERS64* loaded_headers =
      (const IMAGE_NT_HEADERS64*)((const unsigned char*)module + loaded_dos->e_lfanew);
  const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(loaded_headers);
  const unsigned char* record = NULL;
  for (unsigned i = 0; i < loaded_headers->FileHeader.NumberOfSections; ++i) {
    if (memcmp(sections[i].Name, ".obfsc\0\0", IMAGE_SIZEOF_SHORT_NAME) == 0 &&
        sections[i].Misc.VirtualSize == 96) {
      record = (const unsigned char*)module + sections[i].VirtualAddress;
    }
  }
  FARPROC anchor = GetProcAddress(module, "relocation_anchor");
  if (record == NULL || anchor == NULL) {
    result = fail("missing checksum record or relocation anchor");
    goto done;
  }
  int32_t delta;
  uint32_t upper;
  uintptr_t relocated_target;
  memcpy(&delta, record + 0x20, sizeof(delta));
  memcpy(&upper, record + 0x24, sizeof(upper));
  memcpy(&relocated_target, (const void*)anchor, sizeof(relocated_target));
  if (upper != 0 || relocated_target != (uintptr_t)record + (intptr_t)delta ||
      relocated_target < (uintptr_t)module ||
      relocated_target >= (uintptr_t)module + image_size) {
    result = fail("record-relative target and relocated data pointer disagree");
    goto done;
  }
  printf("SELF_CHECKSUM_DLL_REBASED preferred=0x%llx actual=0x%llx fixup=DIR64\n",
         (unsigned long long)preferred, (unsigned long long)(uintptr_t)module);

  typedef uint64_t (*protected_function)(uint64_t);
  protected_function function = (protected_function)GetProcAddress(module, "protected");
  if (function == NULL) {
    result = fail("protected export is missing");
    goto done;
  }
  puts("SELF_CHECKSUM_DLL_CALL");
  fflush(stdout);
  uint64_t value = function(39);
  if (value != 42) {
    printf("SELF_CHECKSUM_DLL_TAMPER actual=0x%llx expected=0x2a\n",
           (unsigned long long)value);
    result = 1;
  } else {
    puts("SELF_CHECKSUM_DLL_PASS");
    result = 0;
  }

done:
  if (module != NULL) {
    FreeLibrary(module);
  }
  if (reservation != NULL) {
    VirtualFree(reservation, 0, MEM_RELEASE);
  }
  return result;
}
