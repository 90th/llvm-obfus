#include <signal.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#endif

int main(int argc, char** argv) {
  if (argc != 2) { return 2; }
  if (strcmp(argv[1], "illegal") == 0) { __builtin_trap(); }
  if (strcmp(argv[1], "breakpoint") == 0) {
#if defined(_WIN32)
    DebugBreak();
#else
    raise(SIGTRAP);
#endif
  } else if (strcmp(argv[1], "access-violation") == 0) {
#if defined(_WIN32)
    RaiseException(0xC0000005u, EXCEPTION_NONCONTINUABLE, 0, NULL);
#else
    raise(SIGSEGV);
#endif
  } else if (strcmp(argv[1], "wait") == 0) {
#if defined(_WIN32)
    Sleep(10000);
#else
    sleep(10);
#endif
  } else if (strcmp(argv[1], "failure") == 0) {
    return 1;
  }
  return 0;
}
