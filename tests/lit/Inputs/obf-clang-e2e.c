#include <stdio.h>
#include <string.h>

static int checksum(const char *s) {
  int a = 0x1505;
  for (int i = 0; s[i]; i++) a = ((a << 5) + a) ^ (unsigned char)s[i];
  return a & 0xffff;
}

int main(void) {
  const char *tag = "obf-e2e-check";
  int first = checksum(tag);
  int second = checksum(tag);
  printf("consistent=%d len=%d\n", (first == second), (int)strlen(tag));
  return 0;
}
