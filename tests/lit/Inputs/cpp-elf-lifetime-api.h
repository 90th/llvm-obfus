#ifndef CPP_ELF_LIFETIME_API_H
#define CPP_ELF_LIFETIME_API_H

#include <cstdint>

using U = std::uint64_t;

enum LifetimeStage : unsigned {
  GLOBAL_CTOR = 1,
  LOCAL_ATTEMPT = 2,
  LOCAL_CLEANUP = 3,
  LOCAL_CTOR = 4,
  LOCAL_CATCH = 5,
  TLS_CTOR = 6,
  TOUCH = 7,
  TLS_DTOR = 8,
  LOCAL_DTOR = 9,
  GLOBAL_DTOR = 10,
};

extern "C" {
U lifetime_generation() noexcept;
void lifetime_observe(unsigned stage, U generation, U result, U effect) noexcept;

void lifetime_local_initialize();
U lifetime_touch();
U lifetime_snapshot() noexcept;

U lifetime_text(U stage);
U lifetime_vm(U stage, U generation, U previous, U text);
U lifetime_step(U stage, U generation, U *effect);
}

#endif
