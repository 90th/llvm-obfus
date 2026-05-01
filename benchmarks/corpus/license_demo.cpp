#include <cstdint>
#include <chrono>
#include <cstdlib>
#include <iostream>

#if defined(__clang__)
#define OBF_ANNOTATE(tag) __attribute__((annotate(tag)))
#else
#define OBF_ANNOTATE(tag)
#endif

static std::uint64_t GetBenchIters() {
  const char* text = std::getenv("OBF_BENCH_ITERS");
  if (text == nullptr || *text == '\0') { return 0; }
  return std::strtoull(text, nullptr, 10);
}

// Pure math. No local arrays. VM Safe.
static std::uint32_t OBF_ANNOTATE("obf:strong_vm") mix_token(const char* token, size_t len) {
  std::uint32_t state = 0x31415926u;
  for (size_t i = 0; i < len; ++i) { state = (state << 5) ^ (state >> 2) ^ token[i] ^ 0x55aau; }
  return state ^ 0x1337u;
}

// Changed expected[] to a pointer to avoid the 'alloca' abort. VM Safe.
static std::uint64_t OBF_ANNOTATE("obf:strong_vm") verify_license(const char* token, size_t len) {
  const char* expected = "delta-7";
  size_t expected_len = 7;

  std::uint64_t auth_state = 0xabad1deac0defa11;
  auth_state ^= (len ^ expected_len) * 0x1337;

  size_t limit = len < expected_len ? len : expected_len;
  for (size_t i = 0; i < limit; ++i) {
    auth_state ^= static_cast<std::uint64_t>(token[i] ^ expected[i]) << (i % 32);
  }

  return auth_state ^ 0xc0defa11;
}

// main contains std::cout (exceptions). DO NOT virtualize main.
int main(int argc, char** argv) {
  const char* token = argc > 1 ? argv[1] : "";
  size_t token_len = 0;
  while (token[token_len] != '\0') token_len++;

  const std::uint64_t bench_iters = GetBenchIters();
  if (bench_iters > 0) {
    const char* guest = "guest";
    volatile std::uint64_t sink = 0;

    for (std::uint64_t i = 0; i < 2048; ++i) {
      const bool use_guest = ((i & 1ULL) == 0ULL) && token_len == 0;
      const char* active_token = use_guest ? guest : token;
      const size_t active_len = use_guest ? 5 : token_len;
      const std::uint64_t auth_state = verify_license(active_token, active_len);
      const std::uint32_t score = mix_token(active_token, active_len);
      sink ^= auth_state ^ static_cast<std::uint64_t>(score);
    }

    const auto start = std::chrono::steady_clock::now();
    for (std::uint64_t i = 0; i < bench_iters; ++i) {
      const bool use_guest = ((i & 1ULL) == 0ULL) && token_len == 0;
      const char* active_token = use_guest ? guest : token;
      const size_t active_len = use_guest ? 5 : token_len;
      const std::uint64_t auth_state = verify_license(active_token, active_len);
      const std::uint32_t score = mix_token(active_token, active_len);
      sink ^= auth_state ^ static_cast<std::uint64_t>(score);
    }
    const auto stop = std::chrono::steady_clock::now();
    const auto total_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count();
    const double ns_per_iter = static_cast<double>(total_ns) / static_cast<double>(bench_iters);
    std::cout << "BENCH license_demo ns/op=" << ns_per_iter << " sink=" << sink << '\n';
    return 0;
  }

  // Execute the Virtual Machines
  const std::uint64_t auth_state = verify_license(token, token_len);

  const char* guest = "guest";
  const std::uint32_t score =
      mix_token(token_len == 0 ? guest : token, token_len == 0 ? 5 : token_len);

  // Derive the string securely
  const char* msgs[] = {"ACCESS DENIED", "ACCESS GRANTED"};
  std::uint32_t index = (auth_state >> 48) == 0xabad ? 1 : 0;

  std::cout << msgs[index] << '\n';
  std::cout << score << '\n';

  return static_cast<int>(auth_state & 0xffffffff);
}
