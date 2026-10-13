#ifndef CPP_PE_LIFETIME_API_H
#define CPP_PE_LIFETIME_API_H
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <stdint.h>
using U = uint64_t;
enum Stage : unsigned {
  GLOBAL_FIRST = 1, GLOBAL_SECOND, ATTACH, LOCAL_ATTEMPT, MEMBER_FIRST,
  LOCAL_ROLLBACK, LOCAL_CATCH, MEMBER_SECOND, LOCAL_READY, TOUCH,
  TLS_FIRST, TLS_SECOND, TLS_SECOND_DTOR, TLS_FIRST_DTOR,
  FLS_READY, FLS_DTOR, LOCAL_DTOR, MEMBER_SECOND_DTOR, MEMBER_FIRST_DTOR,
  DETACH_DYNAMIC, DETACH_PROCESS, GLOBAL_SECOND_DTOR, GLOBAL_FIRST_DTOR,
  SEH_CAUGHT, WORK_READY, WORK_STOP
};
struct Event { unsigned stage; U result; U effect; DWORD thread; };
struct LifetimeLog { volatile LONG count; U effect; Event events[256]; };
extern "C" U lifetime_text(U stage);
extern "C" U lifetime_vm(U stage, U previous, U text);
extern "C" U lifetime_step(U stage, U *effect);
#ifdef BUILD_LIBRARY
#define API extern "C" __declspec(dllexport) __attribute__((noinline))
#else
#define API extern "C"
#endif
API U lifetime_touch();
API U lifetime_snapshot();
API int lifetime_fls_enter();
API int lifetime_fls_leave();
API int lifetime_shutdown();
API U lifetime_seh();
API U lifetime_worker(HANDLE ready, HANDLE stop);
#endif
