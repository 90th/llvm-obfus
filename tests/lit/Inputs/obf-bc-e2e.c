#include <stdio.h>
#include <string.h>

__attribute__((noinline))
int protected_value(const char *input, int value) {
  static const char secret[] = "obf-bc";
  const int matched = strcmp(input, secret) == 0;
  return value * 7 + (matched ? 3 : 5);
}

__attribute__((noinline))
int unmatched_value(int value) {
  return value + 29;
}

int main(void) {
  const int selected = protected_value("", 5);
  const int unmatched = unmatched_value(8);
  printf("sum=%d\n", selected + unmatched);
  return 0;
}
