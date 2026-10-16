#include <atomic>
#include <cstdint>
#include <cstdio>
#include <thread>

using U = std::uint64_t;
struct Big {
  U a, b, c;
};
#define NOINLINE __attribute__((noinline))

extern "C" NOINLINE U target_scalar(U a, U b, U c, U d, U e, U f, U g, U h, U* effect) noexcept {
  U result = a + 3 * b + 5 * c + 7 * d + 11 * e + 13 * f + 17 * g + 19 * h;
  *effect ^= result;
  return result;
}
extern "C" NOINLINE U proxy_scalar(U x, U* effect) noexcept {
  return target_scalar(x, x + 1, x + 2, x + 3, x + 4, x + 5, x + 6, x + 7, effect);
}
extern "C" NOINLINE Big target_aggregate(Big value, double factor) noexcept {
  return {value.c + static_cast<U>(factor), value.a ^ 0x123456789abcdef0ULL, value.b * 7};
}
extern "C" NOINLINE Big proxy_aggregate(Big value, double factor) noexcept {
  return target_aggregate(value, factor);
}
extern "C" NOINLINE double target_fp(double a, float b, int c) noexcept {
  return a * 2.0 + static_cast<double>(b) - c;
}
extern "C" NOINLINE double proxy_fp(double a, float b, int c) noexcept {
  return target_fp(a, b, c);
}
extern "C" NOINLINE int target_throw(int value) {
  if (value < 0) throw value;
  return value * 37 + 9;
}
extern "C" NOINLINE int proxy_throw(int value) { return target_throw(value); }
extern "C" NOINLINE U proxy_reentry(unsigned depth, U value);
extern "C" NOINLINE U target_reentry(unsigned depth, U value) {
  return depth ? proxy_reentry(depth - 1, value + 7) + 3 : value;
}
extern "C" NOINLINE U proxy_reentry(unsigned depth, U value) {
  return target_reentry(depth, value);
}
extern "C" NOINLINE U proxy_tail_peer(U remaining, U result);
extern "C" NOINLINE U proxy_tail(U remaining, U result) {
  if (remaining == 0) return result;
  [[clang::musttail]] return proxy_tail_peer(remaining - 1, result + remaining);
}
extern "C" NOINLINE U proxy_tail_peer(U remaining, U result) {
  if (remaining == 0) return result;
  [[clang::musttail]] return proxy_tail(remaining - 1, result + remaining);
}
extern "C" NOINLINE U proxy_loop(unsigned count, U* effect) noexcept {
  U total = 0;
  for (unsigned i = 0; i < count; ++i) total += target_scalar(i, 1, 2, 3, 4, 5, 6, 7, effect);
  return total;
}
extern "C" NOINLINE int proxy_vm_target(int value) noexcept { return ((value * 37) ^ 0x1234) + 19; }
extern "C" NOINLINE int vm_consumer(int value) noexcept { return proxy_vm_target(value); }

static bool check_unwind() {
  try {
    (void)proxy_throw(-29);
    return false;
  } catch (int value) { return value == -29 && proxy_throw(5) == 194; }
}

int main() {
  U effect = 0;
  const U scalar = proxy_scalar(17, &effect);
  if (scalar != 1670 || effect != 1670) return 11;
  Big aggregate = proxy_aggregate({11, 13, 17}, 4.0);
  if (aggregate.a != 21 || aggregate.b != (11 ^ 0x123456789abcdef0ULL) || aggregate.c != 91)
    return 12;
  if (proxy_fp(3.25, 1.5f, -7) != 15.0) return 13;
  if (!check_unwind()) return 14;
  if (proxy_reentry(7, 5) != 75) return 15;
  if (vm_consumer(31) != (((31 * 37) ^ 0x1234) + 19)) return 16;
  constexpr U depth = 1000000;
  if (proxy_tail(depth, 7) != depth * (depth + 1) / 2 + 7) return 17;
  effect = 0;
  U expected_effect = 0;
  U expected_total = 0;
  for (unsigned i = 0; i < 10000; ++i) {
    const U value = i + 3 + 10 + 21 + 44 + 65 + 102 + 133;
    expected_effect ^= value;
    expected_total += value;
  }
  if (proxy_loop(10000, &effect) != expected_total || effect != expected_effect) return 18;
  std::atomic<bool> correct{true};
  {
    std::thread workers[4];
    for (unsigned t = 0; t < 4; ++t) {
      workers[t] = std::thread([t, &correct] {
        U local = 0;
        U expected = 0;
        for (unsigned i = 0; i < 1000; ++i) {
          U x = i + t;
          U value = x + 3 * (x + 1) + 5 * (x + 2) + 7 * (x + 3) + 11 * (x + 4) + 13 * (x + 5) +
                    17 * (x + 6) + 19 * (x + 7);
          expected ^= value;
          if (proxy_scalar(x, &local) != value || local != expected) correct = false;
        }
      });
    }
    for (auto& worker : workers) worker.join();
  }
  if (!correct) return 19;
  return 0;
}
