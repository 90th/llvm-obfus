#include "cpp-elf-lifetime-api.h"

#ifndef RAW_CONTROL
extern "C" __attribute__((noinline)) U lifetime_text(U stage) {
  static const char payload[] = "lifecycle-auth-v1-payload";
  return static_cast<unsigned char>(payload[stage % 25]);
}

extern "C" __attribute__((noinline)) U lifetime_vm(U stage, U generation,
                                                U previous, U text) {
  U mixed = previous + generation * UINT64_C(0x9e3779b97f4a7c15) +
            stage * UINT64_C(0x100000001b3);
  return ((mixed << 11) | (mixed >> 53)) ^
         (text * UINT64_C(0xa0761d6478bd642f));
}

extern "C" __attribute__((noinline)) U lifetime_step(U stage, U generation,
                                                  U *effect) {
  U text = lifetime_text(stage);
  U value = lifetime_vm(stage, generation, *effect, text);
  *effect = value + stage * 13;
  return value ^ *effect;
}
#endif

namespace {
U generation = 0;
U effect = 0;
bool first_attempt_failed = false;

// Retained native code supplies a relocation-free checksum sample, not events.
volatile U sampled_anchor_first = UINT64_C(0xe15bd312caf09763);
volatile U sampled_anchor_second = UINT64_C(0x8ebc6af09c88c6e3);
__attribute__((noinline, used)) U lifetime_sampled_sibling(U input) {
  U first = sampled_anchor_first;
  U second = sampled_anchor_second;
  return ((input ^ first) * UINT64_C(0x9e3779b97f4a7c15)) + (second >> 3);
}

U emit(unsigned stage) noexcept {
  U result = lifetime_step(stage, generation, &effect);
  lifetime_observe(stage, generation, result, effect);
  return result;
}

struct Global {
  Global() noexcept {
    generation = lifetime_generation();
    emit(GLOBAL_CTOR);
  }
  ~Global() noexcept { emit(GLOBAL_DTOR); }
};
Global global;

struct RetryFailure {
  U payload;
};

struct FailureCleanup {
  bool active = true;
  ~FailureCleanup() noexcept {
    if (active)
      emit(LOCAL_CLEANUP);
  }
};

struct Local {
  Local() {
    emit(LOCAL_ATTEMPT);
    FailureCleanup cleanup;
    if (!first_attempt_failed) {
      first_attempt_failed = true;
      throw RetryFailure{0x51};
    }
    cleanup.active = false;
    emit(LOCAL_CTOR);
  }
  ~Local() noexcept { emit(LOCAL_DTOR); }
};

struct ThreadLifetime {
  ThreadLifetime() noexcept { emit(TLS_CTOR); }
  ~ThreadLifetime() noexcept { emit(TLS_DTOR); }
};
} // namespace

extern "C" __attribute__((noinline)) void lifetime_local_initialize() {
  static Local local;
  (void)local;
}

extern "C" __attribute__((noinline)) U lifetime_touch() {
  try {
    lifetime_local_initialize();
    static thread_local ThreadLifetime thread;
    (void)thread;
    return emit(TOUCH);
  } catch (const RetryFailure &failure) {
    if (failure.payload != 0x51)
      throw;
    emit(LOCAL_CATCH);
    return UINT64_MAX;
  }
}

extern "C" __attribute__((noinline)) U lifetime_snapshot() noexcept {
  return effect;
}
