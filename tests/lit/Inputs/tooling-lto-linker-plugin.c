#include <stdio.h>

static __attribute__((noinline)) int checksum(const char *s) {
  int a = 0x1505;
  for (int i = 0; s[i]; ++i) a = ((a << 5) + a) ^ (unsigned char)s[i];
  return a & 0xffff;
}

static __attribute__((noinline)) int fold(int x) {
  return (x ^ 0x1234) + 85;
}

int main(void) {
  const char *tag = "lto-linkonly-secret";
  int first = checksum(tag);
  int second = checksum(tag);
  int folded = fold(42);
  printf("link-lto consistent=%d value=%d\n", first == second, folded);
  return (first == second && folded == 4723) ? 0 : 1;
}
