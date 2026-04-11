#include <stdio.h>

int wpo_check(const char *token);
int wpo_mix(const char *token);

int main(int argc, char **argv) {
  const char *token = argc > 1 ? argv[1] : "guest";
  const int ok = wpo_check(token);
  const int score = wpo_mix(token);
  puts(ok ? "WPO OK" : "WPO FAIL");
  printf("%d\n", score);
  return ok ? 0 : 1;
}
