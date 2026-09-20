#define _GNU_SOURCE
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

__attribute__((noinline)) int compare_string(const char* value) {
  return strcmp(value, "apple") == 0;
}

__attribute__((noinline)) int compare_bounded(const char* value) {
  return strncmp("apple", value, 64) == 0;
}

__attribute__((noinline)) int compare_zero(const char* value) {
  return strncmp("apple", value, 0) == 0;
}

int main(void) {
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) { return 1; }
  size_t size = (size_t)page_size;
  char* pages = mmap(NULL, size * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (pages == MAP_FAILED) { return 2; }
  if (mprotect(pages + size, size, PROT_NONE) != 0) { return 3; }

  char* short_string = pages + size - 2;
  short_string[0] = 'x';
  short_string[1] = '\0';
  if (compare_string(short_string) || compare_bounded(short_string)) { return 4; }
  short_string[0] = 'a';
  if (compare_string(short_string) || compare_bounded(short_string)) { return 5; }
  if (compare_string(short_string + 1) || compare_bounded(short_string + 1)) { return 6; }
  if (!compare_zero(pages + size)) { return 7; }

  char* equal_string = pages + size - 6;
  memcpy(equal_string, "apple", 6);
  if (!compare_string(equal_string) || !compare_bounded(equal_string)) { return 8; }
  return munmap(pages, size * 2) == 0 ? 0 : 9;
}
