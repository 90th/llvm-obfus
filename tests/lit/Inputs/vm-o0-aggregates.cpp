#include <cstdint>
#include <cstdio>

// Exercise the audited Windows x64 aggregate ABI on both native test hosts.
#if defined(__x86_64__) && !defined(_WIN32)
#define AGGREGATE_ABI __attribute__((ms_abi))
#else
#define AGGREGATE_ABI
#endif

struct S8 {
  std::uint64_t value;
};

struct TwoFloats {
  float first;
  float second;
};

static_assert(sizeof(S8) == 8);
static_assert(sizeof(TwoFloats) == 8);

unsigned aggregate_effect_count = 0;

extern "C" AGGREGATE_ABI __attribute__((noinline)) std::uint64_t
obf_o0_param8(S8 input, std::uint64_t* effect) noexcept {
  *effect = *effect + input.value + 3;
  aggregate_effect_count = aggregate_effect_count + 1;
  return (input.value ^ UINT64_C(0xf0e1d2c3b4a59687)) + 17;
}

extern "C" AGGREGATE_ABI __attribute__((noinline)) S8
obf_o0_return8(std::uint64_t input, std::uint64_t* effect) noexcept {
  S8 result{input * 3 + 5};
  *effect = *effect ^ (result.value + 7);
  aggregate_effect_count = aggregate_effect_count + 1;
  return result;
}

extern "C" AGGREGATE_ABI __attribute__((noinline)) std::int64_t
obf_o0_two_floats(TwoFloats input, std::uint64_t* effect) noexcept {
  const std::int64_t result = static_cast<std::int64_t>(input.first + input.second);
  *effect = *effect + static_cast<std::uint64_t>(result + 16);
  aggregate_effect_count = aggregate_effect_count + 1;
  return result;
}

#ifdef OBF_TEST_ESCAPE
volatile unsigned char* escaped_buffer = nullptr;

__attribute__((noinline)) std::uint64_t observe_buffer() noexcept {
  return escaped_buffer[0] + escaped_buffer[31];
}

extern "C" __attribute__((noinline)) std::uint64_t
obf_o0_escaping_buffer(std::uint64_t input) noexcept {
  unsigned char buffer[32];
  buffer[0] = static_cast<unsigned char>(input);
  buffer[31] = 19;
  escaped_buffer = buffer;
  const std::uint64_t result = observe_buffer();
  escaped_buffer = nullptr;
  return result;
}
#endif

int main() {
  struct IntegerCase {
    std::uint64_t input;
    std::uint64_t parameter_result;
    std::uint64_t parameter_effect;
    std::uint64_t returned_value;
    std::uint64_t return_effect;
  };
  const IntegerCase integers[] = {
      {UINT64_C(0x0000000000000000),
       UINT64_C(0xf0e1d2c3b4a59698),
       UINT64_C(0x1020304050607083),
       UINT64_C(0x0000000000000005),
       UINT64_C(0x102030405060708c)},
      {UINT64_C(0x123456789abcdef0),
       UINT64_C(0xe2d584bb2e194888),
       UINT64_C(0x225486b8eb1d4f73),
       UINT64_C(0x369d0369d0369cd5),
       UINT64_C(0x26bd33298056ec5c)},
      {UINT64_C(0xffffffffffffffff),
       UINT64_C(0x0f1e2d3c4b5a6989),
       UINT64_C(0x1020304050607082),
       UINT64_C(0x0000000000000002),
       UINT64_C(0x1020304050607089)},
  };
  for (const IntegerCase& test : integers) {
    std::uint64_t effect = UINT64_C(0x1020304050607080);
    if (obf_o0_param8(S8{test.input}, &effect) != test.parameter_result ||
        effect != test.parameter_effect) {
      return 1;
    }
    effect = UINT64_C(0x1020304050607080);
    const S8 returned = obf_o0_return8(test.input, &effect);
    if (returned.value != test.returned_value || effect != test.return_effect) { return 2; }
  }

  struct FloatCase {
    TwoFloats input;
    std::int64_t result;
    std::uint64_t effect;
  };
  const FloatCase floats[] = {
      {{1.5F, -2.25F}, 0, 116},
      {{-3.0F, 4.5F}, 1, 117},
      {{0.5F, 8.0F}, 8, 124},
  };
  for (const FloatCase& test : floats) {
    std::uint64_t effect = 100;
    if (obf_o0_two_floats(test.input, &effect) != test.result || effect != test.effect) {
      return 3;
    }
  }
  if (aggregate_effect_count != 9) { return 4; }
#ifdef OBF_TEST_ESCAPE
  if (obf_o0_escaping_buffer(7) != 26 || escaped_buffer != nullptr) { return 5; }
#endif
  std::printf("O0_AGGREGATES_OK param8=3 return8=3 floats=3 effects=%u\n", aggregate_effect_count);
  return 0;
}
