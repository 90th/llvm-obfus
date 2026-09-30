#include <pthread.h>

#ifdef OBF_CACHE_TARGETS
__attribute__((noinline)) int cache_target(int x) {
  int mixed = (x ^ 0x5a) + 7;
  return mixed * 3 - 1;
}

__attribute__((noinline)) int callsite_user(int x) { return cache_target(x) + 1; }
#else
extern int cache_target(int x);
extern int callsite_user(int x);
static int (*volatile g_wrapper_target)(int) = cache_target;

static int expected_cache(int x) {
  int mixed = (x ^ 0x5a) + 7;
  return mixed * 3 - 1;
}

static int expected_callsite(int x) { return expected_cache(x) + 1; }

struct ThreadState {
  int mode;
  int input;
  int output;
};

static pthread_barrier_t g_start;

static void* run_thread(void* raw) {
  struct ThreadState* state = (struct ThreadState*)raw;
  int barrier_status = pthread_barrier_wait(&g_start);
  if (barrier_status != 0 && barrier_status != PTHREAD_BARRIER_SERIAL_THREAD) {
    state->output = -1;
    return 0;
  }

  state->output =
      state->mode == 0 ? g_wrapper_target(state->input) : callsite_user(state->input);
  return 0;
}

int main(void) {
  pthread_t direct_thread;
  pthread_t callsite_thread;
  struct ThreadState direct = {0, 11, 0};
  struct ThreadState via = {1, 13, 0};

  if (pthread_barrier_init(&g_start, 0, 3) != 0) { return 11; }
  if (pthread_create(&direct_thread, 0, run_thread, &direct) != 0) { return 12; }
  if (pthread_create(&callsite_thread, 0, run_thread, &via) != 0) { return 13; }

  {
    int barrier_status = pthread_barrier_wait(&g_start);
    if (barrier_status != 0 && barrier_status != PTHREAD_BARRIER_SERIAL_THREAD) { return 14; }
  }
  if (pthread_join(direct_thread, 0) != 0) { return 15; }
  if (pthread_join(callsite_thread, 0) != 0) { return 16; }
  if (pthread_barrier_destroy(&g_start) != 0) { return 17; }

  if (direct.output != expected_cache(direct.input)) { return 1; }
  if (via.output != expected_callsite(via.input)) { return 2; }
  if (g_wrapper_target(17) != expected_cache(17)) { return 3; }
  if (callsite_user(19) != expected_callsite(19)) { return 4; }
  return 0;
}
#endif
