#include <stdio.h>

__attribute__((noinline)) static int progress_strong_vm(int x) {
  int folded = x + 3;
  int masked = folded ^ 5;
  return masked - 2;
}

int main(int argc, char **argv) {
  (void)argv;
  int result = progress_strong_vm(argc + 10);
  printf("result=%d\n", result);
  return 0;
}
