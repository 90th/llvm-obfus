__attribute__((used, noinline)) static int sibling(int x) { return x + 7; }
__attribute__((noinline)) static int protected(int x) { return x + 3; }
static int (*volatile protected_entry)(int) = protected;

__declspec(dllexport) int self_checksum_dll_entry(void) {
  return protected_entry(39);
}
