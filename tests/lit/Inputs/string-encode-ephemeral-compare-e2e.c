#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(_MSC_VER)
#define OBF_NOINLINE __declspec(noinline)
#else
#define OBF_NOINLINE __attribute__((noinline))
#endif

static int g_failures = 0;
static int g_checks = 0;

static inline int sign_of(int v) {
  return (v > 0) - (v < 0);
}

#define CHECK_CMP(name, transformed_expr, baseline_expr) do { \
  g_checks++; \
  int t_res = (transformed_expr); \
  int b_res = (baseline_expr); \
  if (sign_of(t_res) != sign_of(b_res)) { \
    fprintf(stderr, "[FAIL] %s: transformed=%d (sign=%d) vs baseline=%d (sign=%d)\n", \
            name, t_res, sign_of(t_res), b_res, sign_of(b_res)); \
    g_failures++; \
  } else if ((b_res == 0 && t_res != 0) || (b_res != 0 && t_res == 0)) { \
    fprintf(stderr, "[FAIL] %s: zero-mismatch: transformed=%d vs baseline=%d\n", \
            name, t_res, b_res); \
    g_failures++; \
  } \
} while(0)

// Dedicated immutable globals used only by protected test_* functions. Eligible
// calls must still be present when llvm-obfus runs at OptimizerLast.
static const char g_ephem_mem64_eq[65] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char g_ephem_mem64_diff_first[65] = "X123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char g_ephem_mem64_diff_mid[65] = "0123456789abcdef0123456789abcdeX0123456789abcdef0123456789abcdef";
static const char g_ephem_mem64_diff_last[65] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeX";
static const char g_ephem_mem64_high[65] = "\xfe""123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char g_ephem_mem64_low[65]  = "\x02""123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char g_ephem_mem64_rhs[65] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

static const char g_ephem_strcmp_hello[6] = "hello";
static const char g_ephem_strcmp_high[6] = "h\xffllo";
static const char g_ephem_strcmp_low[6] = "h\x01llo";
static const char g_ephem_strcmp_short_a[4] = "abc";
static const char g_ephem_strcmp_short_b[7] = "abcdef";
static const char g_ephem_strcmp_rhs[6] = "hello";

static const char g_ephem_strncmp_mem64[65] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char g_ephem_strncmp_diff_first[65] = "X123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char g_ephem_strncmp_hello[6] = "hello";
static const char g_ephem_strncmp_short_a[4] = "abc";
static const char g_ephem_strncmp_short_b[7] = "abcdef";

// Dedicated sentinel globals used by release-proof probe functions. These
// plaintexts intentionally do not appear in the runtime reference setup.
static const char g_probe_memcmp[65] = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
static const char g_probe_strcmp[] = "ephemeral-probe-s";
static const char g_probe_strncmp[] = "ephemeral-probe-n-0123456789abcdef";

// Dedicated globals for fallback scenarios.
static const char g_fallback_mem65_eq[66] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefZ";
static const char g_fallback_mem65_diff[66] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefY";
static const char g_fallback_mem_dynamic[65] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char g_fallback_pair_1[8] = "pair_11";
static const char g_fallback_pair_2[8] = "pair_22";
static const char g_fallback_str65_a[66] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
static const char g_fallback_strncmp_65[66] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefZ";
static const char g_fallback_strncmp_dynamic[6] = "hello";

// Mutable runtime reference buffers are initialized only by an unprotected
// function. No protected plaintext string literal is repeated here: building
// the bytes algorithmically prevents LLVM from merging a protected constant
// with an unprotected reference literal before string_encoding runs.
static char r64_eq[65];
static char r64_diff_first[65];
static char r64_diff_mid[65];
static char r64_diff_last[65];
static char r64_high[65];
static char r64_low[65];
static char r65_eq[66];
static char r65_diff[66];
static char r_hello[6];
static char r_world[6];
static char r_hellz[6];
static char r_aello[6];
static char r_zello[6];
static char r_short_a[4];
static char r_short_b[7];
static char r_high[6];
static char r_low[6];
static char r_abc_xyz[7];
static char r_pair_1[8];
static char r_pair_2[8];
static char r_str65_a[66];

static volatile unsigned char g_runtime_bias = 0;
volatile uint64_t v_64 = 64;

// Deliberately outside the test_* policy target. The volatile-dependent
// construction keeps the reference buffers runtime-unknown at O1/O2/O3 while
// avoiding duplicate plaintext globals that could be merged with protected
// constants.
OBF_NOINLINE static void prepare_runtime_inputs(void) {
  const unsigned char bias = g_runtime_bias;

  for (size_t i = 0; i < 64; ++i) {
    const unsigned x = (unsigned)(i & 15u);
    const unsigned char base =
        (unsigned char)(x < 10u ? ('0' + x) : ('a' + (x - 10u)));
    r64_eq[i] = (char)(base + bias);
    r64_diff_first[i] = (char)(((i == 0) ? (unsigned char)'X' : base) + bias);
    r64_diff_mid[i] = (char)(((i == 31) ? (unsigned char)'X' : base) + bias);
    r64_diff_last[i] = (char)(((i == 63) ? (unsigned char)'X' : base) + bias);
    r64_high[i] = (char)(((i == 0) ? (unsigned char)0xfe : base) + bias);
    r64_low[i] = (char)(((i == 0) ? (unsigned char)0x02 : base) + bias);
    r65_eq[i] = (char)(base + bias);
    r65_diff[i] = (char)(base + bias);
  }
  r64_eq[64] = (char)bias;
  r64_diff_first[64] = (char)bias;
  r64_diff_mid[64] = (char)bias;
  r64_diff_last[64] = (char)bias;
  r64_high[64] = (char)bias;
  r64_low[64] = (char)bias;
  r65_eq[64] = (char)((unsigned char)'Z' + bias);
  r65_diff[64] = (char)((unsigned char)'Y' + bias);
  r65_eq[65] = (char)bias;
  r65_diff[65] = (char)bias;

#define SET_BYTE(buf, idx, value) \
  ((buf)[(idx)] = (char)((unsigned char)(value) + bias))
#define TERM(buf, idx) ((buf)[(idx)] = (char)bias)

  SET_BYTE(r_hello, 0, 'h'); SET_BYTE(r_hello, 1, 'e');
  SET_BYTE(r_hello, 2, 'l'); SET_BYTE(r_hello, 3, 'l');
  SET_BYTE(r_hello, 4, 'o'); TERM(r_hello, 5);

  SET_BYTE(r_world, 0, 'w'); SET_BYTE(r_world, 1, 'o');
  SET_BYTE(r_world, 2, 'r'); SET_BYTE(r_world, 3, 'l');
  SET_BYTE(r_world, 4, 'd'); TERM(r_world, 5);

  SET_BYTE(r_hellz, 0, 'h'); SET_BYTE(r_hellz, 1, 'e');
  SET_BYTE(r_hellz, 2, 'l'); SET_BYTE(r_hellz, 3, 'l');
  SET_BYTE(r_hellz, 4, 'z'); TERM(r_hellz, 5);

  SET_BYTE(r_aello, 0, 'a'); SET_BYTE(r_aello, 1, 'e');
  SET_BYTE(r_aello, 2, 'l'); SET_BYTE(r_aello, 3, 'l');
  SET_BYTE(r_aello, 4, 'o'); TERM(r_aello, 5);

  SET_BYTE(r_zello, 0, 'z'); SET_BYTE(r_zello, 1, 'e');
  SET_BYTE(r_zello, 2, 'l'); SET_BYTE(r_zello, 3, 'l');
  SET_BYTE(r_zello, 4, 'o'); TERM(r_zello, 5);

  SET_BYTE(r_short_a, 0, 'a'); SET_BYTE(r_short_a, 1, 'b');
  SET_BYTE(r_short_a, 2, 'c'); TERM(r_short_a, 3);

  SET_BYTE(r_short_b, 0, 'a'); SET_BYTE(r_short_b, 1, 'b');
  SET_BYTE(r_short_b, 2, 'c'); SET_BYTE(r_short_b, 3, 'd');
  SET_BYTE(r_short_b, 4, 'e'); SET_BYTE(r_short_b, 5, 'f');
  TERM(r_short_b, 6);

  SET_BYTE(r_high, 0, 'h'); SET_BYTE(r_high, 1, 0xff);
  SET_BYTE(r_high, 2, 'l'); SET_BYTE(r_high, 3, 'l');
  SET_BYTE(r_high, 4, 'o'); TERM(r_high, 5);

  SET_BYTE(r_low, 0, 'h'); SET_BYTE(r_low, 1, 0x01);
  SET_BYTE(r_low, 2, 'l'); SET_BYTE(r_low, 3, 'l');
  SET_BYTE(r_low, 4, 'o'); TERM(r_low, 5);

  SET_BYTE(r_abc_xyz, 0, 'a'); SET_BYTE(r_abc_xyz, 1, 'b');
  SET_BYTE(r_abc_xyz, 2, 'c'); SET_BYTE(r_abc_xyz, 3, 'X');
  SET_BYTE(r_abc_xyz, 4, 'Y'); SET_BYTE(r_abc_xyz, 5, 'Z');
  TERM(r_abc_xyz, 6);

  SET_BYTE(r_pair_1, 0, 'p'); SET_BYTE(r_pair_1, 1, 'a');
  SET_BYTE(r_pair_1, 2, 'i'); SET_BYTE(r_pair_1, 3, 'r');
  SET_BYTE(r_pair_1, 4, '_'); SET_BYTE(r_pair_1, 5, '1');
  SET_BYTE(r_pair_1, 6, '1'); TERM(r_pair_1, 7);

  SET_BYTE(r_pair_2, 0, 'p'); SET_BYTE(r_pair_2, 1, 'a');
  SET_BYTE(r_pair_2, 2, 'i'); SET_BYTE(r_pair_2, 3, 'r');
  SET_BYTE(r_pair_2, 4, '_'); SET_BYTE(r_pair_2, 5, '2');
  SET_BYTE(r_pair_2, 6, '2'); TERM(r_pair_2, 7);

  for (size_t i = 0; i < 65; ++i) {
    r_str65_a[i] = (char)((unsigned char)'A' + bias);
  }
  TERM(r_str65_a, 65);

#undef TERM
#undef SET_BYTE
}

// External noinline probes provide cleanup-stable symbols for proving that a
// libc comparison survives the normal Clang optimizer but is removed by the
// obfuscating wrapper at each optimization level.
OBF_NOINLINE int test_probe_memcmp(const void* rhs) {
  return memcmp(g_probe_memcmp, rhs, 64);
}

OBF_NOINLINE int test_probe_strcmp(const char* rhs) {
  return strcmp(g_probe_strcmp, rhs);
}

OBF_NOINLINE int test_probe_strncmp(const char* rhs) {
  return strncmp(g_probe_strncmp, rhs, 24);
}

OBF_NOINLINE int oracle_memcmp(const void* lhs, const void* rhs, size_t n) {
  return memcmp(lhs, rhs, n);
}

OBF_NOINLINE int oracle_strcmp(const char* lhs, const char* rhs) {
  return strcmp(lhs, rhs);
}

OBF_NOINLINE int oracle_strncmp(const char* lhs, const char* rhs, size_t n) {
  return strncmp(lhs, rhs, n);
}

OBF_NOINLINE int test_memcmp_suite(void) {
  CHECK_CMP("memcmp n=0", memcmp(g_ephem_mem64_eq, r64_diff_first, 0), oracle_memcmp(r64_eq, r64_diff_first, 0));
  CHECK_CMP("memcmp n=1 eq", memcmp(g_ephem_mem64_eq, r64_eq, 1), oracle_memcmp(r64_eq, r64_eq, 1));
  CHECK_CMP("memcmp n=1 diff", memcmp(g_ephem_mem64_diff_first, r64_eq, 1), oracle_memcmp(r64_diff_first, r64_eq, 1));
  CHECK_CMP("memcmp n=64 LHS eq", memcmp(g_ephem_mem64_eq, r64_eq, 64), oracle_memcmp(r64_eq, r64_eq, 64));
  CHECK_CMP("memcmp n=64 LHS diff first", memcmp(g_ephem_mem64_diff_first, r64_eq, 64), oracle_memcmp(r64_diff_first, r64_eq, 64));
  CHECK_CMP("memcmp n=64 LHS diff mid", memcmp(g_ephem_mem64_diff_mid, r64_eq, 64), oracle_memcmp(r64_diff_mid, r64_eq, 64));
  CHECK_CMP("memcmp n=64 LHS diff last", memcmp(g_ephem_mem64_diff_last, r64_eq, 64), oracle_memcmp(r64_diff_last, r64_eq, 64));
  CHECK_CMP("memcmp n=64 RHS eq", memcmp(r64_eq, g_ephem_mem64_rhs, 64), oracle_memcmp(r64_eq, r64_eq, 64));
  CHECK_CMP("memcmp n=64 RHS diff first", memcmp(r64_eq, g_ephem_mem64_diff_first, 64), oracle_memcmp(r64_eq, r64_diff_first, 64));
  CHECK_CMP("memcmp n=64 RHS diff mid", memcmp(r64_eq, g_ephem_mem64_diff_mid, 64), oracle_memcmp(r64_eq, r64_diff_mid, 64));
  CHECK_CMP("memcmp n=64 RHS diff last", memcmp(r64_eq, g_ephem_mem64_diff_last, 64), oracle_memcmp(r64_eq, r64_diff_last, 64));
  CHECK_CMP("memcmp unsigned LHS >", memcmp(g_ephem_mem64_high, r64_eq, 64), oracle_memcmp(r64_high, r64_eq, 64));
  CHECK_CMP("memcmp unsigned LHS <", memcmp(g_ephem_mem64_low, r64_eq, 64), oracle_memcmp(r64_low, r64_eq, 64));
  CHECK_CMP("memcmp unsigned RHS <", memcmp(r64_eq, g_ephem_mem64_high, 64), oracle_memcmp(r64_eq, r64_high, 64));
  CHECK_CMP("memcmp unsigned RHS >", memcmp(r64_eq, g_ephem_mem64_low, 64), oracle_memcmp(r64_eq, r64_low, 64));
  CHECK_CMP("memcmp n=65 eq", memcmp(g_fallback_mem65_eq, r65_eq, 65), oracle_memcmp(r65_eq, r65_eq, 65));
  CHECK_CMP("memcmp n=65 diff", memcmp(g_fallback_mem65_diff, r65_eq, 65), oracle_memcmp(r65_diff, r65_eq, 65));
  CHECK_CMP("memcmp dynamic n", memcmp(g_fallback_mem_dynamic, r64_eq, (size_t)v_64), oracle_memcmp(r64_eq, r64_eq, (size_t)v_64));
  CHECK_CMP("memcmp two globals", memcmp(g_fallback_pair_1, g_fallback_pair_2, 7), oracle_memcmp(r_pair_1, r_pair_2, 7));
  return g_failures;
}

OBF_NOINLINE int test_strcmp_suite(void) {
  CHECK_CMP("strcmp equal", strcmp(g_ephem_strcmp_hello, r_hello), oracle_strcmp(r_hello, r_hello));
  CHECK_CMP("strcmp lhs < rhs", strcmp(g_ephem_strcmp_hello, r_world), oracle_strcmp(r_hello, r_world));
  CHECK_CMP("strcmp lhs > rhs", strcmp(g_ephem_strcmp_hello, r_aello), oracle_strcmp(r_hello, r_aello));
  CHECK_CMP("strcmp mismatch first", strcmp(g_ephem_strcmp_hello, r_zello), oracle_strcmp(r_hello, r_zello));
  CHECK_CMP("strcmp mismatch last", strcmp(g_ephem_strcmp_hello, r_hellz), oracle_strcmp(r_hello, r_hellz));
  CHECK_CMP("strcmp lhs term first", strcmp(g_ephem_strcmp_short_a, r_short_b), oracle_strcmp(r_short_a, r_short_b));
  CHECK_CMP("strcmp rhs term first", strcmp(g_ephem_strcmp_short_b, r_short_a), oracle_strcmp(r_short_b, r_short_a));
  CHECK_CMP("strcmp high bit", strcmp(g_ephem_strcmp_high, r_low), oracle_strcmp(r_high, r_low));
  CHECK_CMP("strcmp low bit", strcmp(g_ephem_strcmp_low, r_high), oracle_strcmp(r_low, r_high));
  CHECK_CMP("strcmp RHS enc eq", strcmp(r_hello, g_ephem_strcmp_rhs), oracle_strcmp(r_hello, r_hello));
  CHECK_CMP("strcmp oversize eq", strcmp(g_fallback_str65_a, r_str65_a), oracle_strcmp(r_str65_a, r_str65_a));
  CHECK_CMP("strcmp two encrypted", strcmp(g_fallback_pair_1, g_fallback_pair_2), oracle_strcmp(r_pair_1, r_pair_2));
  return g_failures;
}

OBF_NOINLINE int test_strncmp_suite(void) {
  CHECK_CMP("strncmp n=0", strncmp(g_ephem_strncmp_hello, r_world, 0), oracle_strncmp(r_hello, r_world, 0));
  CHECK_CMP("strncmp n=1 eq", strncmp(g_ephem_strncmp_hello, r_hello, 1), oracle_strncmp(r_hello, r_hello, 1));
  CHECK_CMP("strncmp n=1 diff", strncmp(g_ephem_strncmp_diff_first, r64_eq, 1), oracle_strncmp(r64_diff_first, r64_eq, 1));
  CHECK_CMP("strncmp n=1 RHS eq", strncmp(r_hello, g_ephem_strncmp_hello, 1), oracle_strncmp(r_hello, r_hello, 1));
  CHECK_CMP("strncmp eq within n", strncmp(g_ephem_strncmp_hello, r_hellz, 4), oracle_strncmp(r_hello, r_hellz, 4));
  CHECK_CMP("strncmp mismatch before n", strncmp(g_ephem_strncmp_hello, r_hellz, 5), oracle_strncmp(r_hello, r_hellz, 5));
  CHECK_CMP("strncmp NUL before n", strncmp(g_ephem_strncmp_short_a, r_short_b, 64), oracle_strncmp(r_short_a, r_short_b, 64));
  CHECK_CMP("strncmp n before NUL", strncmp(g_ephem_strncmp_short_b, r_abc_xyz, 3), oracle_strncmp(r_short_b, r_abc_xyz, 3));
  CHECK_CMP("strncmp n=64 eq", strncmp(g_ephem_strncmp_mem64, r64_eq, 64), oracle_strncmp(r64_eq, r64_eq, 64));
  CHECK_CMP("strncmp n=64 diff", strncmp(g_ephem_strncmp_diff_first, r64_eq, 64), oracle_strncmp(r64_diff_first, r64_eq, 64));
  CHECK_CMP("strncmp n=65", strncmp(g_fallback_strncmp_65, r65_eq, 65), oracle_strncmp(r65_eq, r65_eq, 65));
  CHECK_CMP("strncmp dynamic n", strncmp(g_fallback_strncmp_dynamic, r_hello, (size_t)v_64), oracle_strncmp(r_hello, r_hello, (size_t)v_64));
  return g_failures;
}

int main(void) {
  prepare_runtime_inputs();
  test_memcmp_suite();
  test_strcmp_suite();
  test_strncmp_suite();

  if (g_failures == 0) {
    printf("[ALL E2E PASS] %d assertions passed\n", g_checks);
    return 0;
  }
  printf("[E2E FAIL] %d of %d assertions failed!\n", g_failures, g_checks);
  return 1;
}
