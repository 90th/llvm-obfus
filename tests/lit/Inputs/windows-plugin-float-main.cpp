#include <bit>
#include <cmath>
#include <cstdint>
#include <cstdio>

extern "C" float protected_float(float);
extern "C" double protected_double(double);

static float reference_float(float value) {
  if (value == 0.0f) return value;
  float scaled = value * 1.5f;
  return scaled > 2.0f ? scaled - 0.25f : scaled + 0.75f;
}

static double reference_double(double value) {
  if (value == 0.0) return value;
  double scaled = value * 1.5;
  return scaled > 2.0 ? scaled - 0.25 : scaled + 0.75;
}

int main() {
  constexpr std::uint32_t floats[] = {
      0, 0x80000000U, 0x3f800000U, 0xbf800000U, 0x40000000U, 0xc0000000U,
      0x7f800000U, 0xff800000U, 0x7fc12345U, 1U, 0x80000001U, 0x7f7fffffU};
  constexpr std::uint64_t doubles[] = {
      0, 0x8000000000000000ULL, 0x3ff0000000000000ULL, 0xbff0000000000000ULL,
      0x4000000000000000ULL, 0xc000000000000000ULL, 0x7ff0000000000000ULL,
      0xfff0000000000000ULL, 0x7ff8123456789abcULL, 1ULL,
      0x8000000000000001ULL, 0x7fefffffffffffffULL};
  unsigned errors = 0;
  for (auto bits : floats) {
    float value = std::bit_cast<float>(bits);
    float actual = protected_float(value);
    float expected = reference_float(value);
    if (std::isnan(expected) ? !std::isnan(actual)
                            : std::bit_cast<std::uint32_t>(actual) !=
                                  std::bit_cast<std::uint32_t>(expected)) {
      ++errors;
    }
  }
  for (auto bits : doubles) {
    double value = std::bit_cast<double>(bits);
    double actual = protected_double(value);
    double expected = reference_double(value);
    if (std::isnan(expected) ? !std::isnan(actual)
                            : std::bit_cast<std::uint64_t>(actual) !=
                                  std::bit_cast<std::uint64_t>(expected)) {
      ++errors;
    }
  }
  std::printf("windows-fp errors=%u\n", errors);
  return errors != 0;
}
