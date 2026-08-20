__attribute__((used, noinline)) static int sibling(int x) { return x + 7; }

__attribute__((noinline)) static int protected(int x) { return x + 3; }

static int (*volatile protected_entry)(int) = protected;

int main(void) {
  const int value = protected_entry(39);
  return value == 42 ? 0 : 1;
}
