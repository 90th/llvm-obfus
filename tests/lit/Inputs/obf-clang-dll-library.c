#include <stdint.h>

static const uint64_t vm_table[4] = {0x11223344ULL, 0x55667788ULL, 0x99aabbccULL, 0xddeeff11ULL};
static const uint64_t strong_table[4] = {0x10203040ULL, 0x50607080ULL, 0x90a0b0c0ULL, 0xd0e0f001ULL};
static uint64_t initialization_value;
static const char *initialization_text;

__declspec(dllexport) const char *dll_vm_text(void);
__declspec(dllexport) const char *dll_strong_vm_text(void);

__declspec(dllexport) __attribute__((noinline))
uint64_t dll_vm(uint64_t value, uint64_t *effect) {
  const char *text = dll_vm_text();
  const uint64_t result = value * 7ULL + vm_table[value & 3ULL] + (unsigned char)text[value & 3ULL];
  *effect += result ^ 0x13579bdfULL;
  return result;
}

__declspec(dllexport) __attribute__((noinline))
uint64_t dll_strong_vm(uint64_t value, uint64_t *effect) {
  const char *text = dll_strong_vm_text();
  const uint64_t result = value * 11ULL + strong_table[value & 3ULL] + (unsigned char)text[value & 3ULL];
  *effect += result ^ 0x2468ace0ULL;
  return result;
}

__declspec(dllexport) __attribute__((noinline))
const char *dll_vm_text(void) {
  return "dll-vm-cold-authenticated";
}

__declspec(dllexport) __attribute__((noinline))
const char *dll_strong_vm_text(void) {
  return "dll-strong-vm-cold-authenticated";
}

__attribute__((noinline)) static uint64_t dll_initialize(const char **text, uint64_t index) {
  const char *message = "dll-initializer-authenticated";
  *text = message;
  return 0x123456789abcdef0ULL + (unsigned char)message[index & 3ULL] - 100ULL;
}

__attribute__((constructor(200))) static void dll_constructor(void) {
  initialization_value = dll_initialize(&initialization_text, 0);
}

__declspec(dllexport) uint64_t dll_init_value(void) {
  return initialization_value;
}

__declspec(dllexport) const char *dll_init_text(void) {
  return initialization_text;
}

__attribute__((used, noinline)) static uint64_t dll_sample_sibling(uint64_t value) {
  return value + 0xabcULL;
}

__declspec(dllexport) __attribute__((noinline))
uint64_t dll_checksum(uint64_t value) {
  return value + 3ULL;
}
