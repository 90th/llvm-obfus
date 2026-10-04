import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


# All three modules use the canonical Clang g++ driver and the shared MS CRT.
# Keep normal DLL/EXE startup; the wrapper supplies its configured obf runtime.
CXX_FLAGS = (
    "-std=c++17",
    "-fexceptions",
    "-fcxx-exceptions",
    "-fno-inline",
    "-fms-runtime-lib=dll",
)
VM_EXPORTS = (
    "abi_param8", "abi_param16", "abi_param24", "abi_packed", "abi_nontrivial",
    "abi_floats", "abi_return8", "abi_stack", "abi_import_scalar",
    "abi_callback_scalar", "abi_import_small", "abi_callback_small",
    "abi_pointer_import", "abi_throw_import", "abi_throw_callback",
)
EXCLUDED_EXPORTS = {
    "abi_address": "strong",
    "abi_eh": "light",
    "abi_cleanup_import": "light",
    "abi_cleanup_callback": "light",
}
CONTROL_CASES = {
    "abi_return16": "boundary",
    "abi_return24": "boundary",
    "abi_big_import": "escaping_alloca",
    "abi_big_callback": "escaping_alloca",
    "abi_incoming": "incoming_invoke",
}

HEADER = r'''
#pragma once
#include <stdint.h>
using U = uint64_t;
struct S8 { U value; };
struct S16 { U a, b; };
struct S24 { U a, b, c; };
#pragma pack(push, 1)
struct Packed { unsigned char tag; U value; uint16_t tail; };
#pragma pack(pop)
struct Floats { float a, b; };
struct Effects { U value; unsigned calls, cleanups; };
struct Counts { unsigned constructed, copied, destroyed; U destruction_sum; };
struct NonTrivial {
  U value;
  Counts *counts;
  __attribute__((noinline)) NonTrivial(U v, Counts *c) noexcept : value(v), counts(c) {
    ++counts->constructed;
  }
  __attribute__((noinline)) NonTrivial(const NonTrivial &v) noexcept
      : value(v.value + 9), counts(v.counts) { ++counts->copied; }
  __attribute__((noinline)) ~NonTrivial() noexcept {
    ++counts->destroyed;
    counts->destruction_sum += value;
  }
};
using ScalarCB = U (*)(int8_t, uint16_t, U, double, U, Effects *) noexcept;
using SmallCB = S8 (*)(S8, U, Effects *) noexcept;
using BigCB = S24 (*)(S24, Effects *) noexcept;
using ThrowCB = int (*)(int, Effects *);
using AddressCB = U (*)(U, Effects *) noexcept;
static_assert(sizeof(S8) == 8 && sizeof(S16) == 16 && sizeof(S24) == 24, "aggregate ABI");
static_assert(sizeof(Packed) == 11 && sizeof(Floats) == 8, "aggregate ABI");
#ifdef BUILD_PROVIDER
#define PROVIDER __declspec(dllexport)
#else
#define PROVIDER __declspec(dllimport)
#endif
extern "C" {
PROVIDER U provider_scalar(int8_t, uint16_t, U, double, U, Effects *) noexcept;
PROVIDER S8 provider_small(S8, U, Effects *) noexcept;
PROVIDER S24 provider_big(S24, Effects *) noexcept;
PROVIDER void provider_pointer(const S24 *, S24 *, Effects *) noexcept;
PROVIDER int provider_throw(int, Effects *);
}
#ifdef BUILD_PROTECTED
#define API __declspec(dllexport)
#else
#define API __declspec(dllimport)
#endif
#define NOINLINE __attribute__((noinline))
#define ROT(x, n) (((x) << (n)) | ((x) >> (64 - (n))))
extern "C" {
API U abi_param8(S8, Effects *) noexcept;
API U abi_param16(S16, Effects *) noexcept;
API U abi_param24(S24, Effects *) noexcept;
API U abi_packed(Packed, Effects *) noexcept;
API U abi_nontrivial(NonTrivial, Effects *) noexcept;
API double abi_floats(Floats, Effects *) noexcept;
API S8 abi_return8(U, Effects *) noexcept;
API U abi_stack(S8, U, U, U, U, U, Effects *) noexcept;
API U abi_import_scalar(int8_t, uint16_t, U, double, U, Effects *) noexcept;
API U abi_callback_scalar(ScalarCB, int8_t, uint16_t, U, double, U, Effects *) noexcept;
API U abi_import_small(S8, U, Effects *) noexcept;
API U abi_callback_small(SmallCB, S8, U, Effects *) noexcept;
API U abi_pointer_import(const S24 *, S24 *, Effects *) noexcept;
API int abi_throw_import(int, Effects *);
API int abi_throw_callback(ThrowCB, int, Effects *);
API U abi_address(U, Effects *) noexcept;
API AddressCB abi_get_address() noexcept;
API int abi_eh(int, Effects *);
API int abi_cleanup_import(int, Effects *);
API int abi_cleanup_callback(ThrowCB, int, Effects *);
API U abi_startup() noexcept;
API S16 abi_return16(U, Effects *) noexcept;
API S24 abi_return24(U, Effects *) noexcept;
API U abi_big_import(S24, Effects *) noexcept;
API U abi_big_callback(BigCB, S24, Effects *) noexcept;
API int abi_incoming(int, Effects *);
API int abi_incoming_caller(int, Effects *);
}
'''

PROVIDER_SOURCE = r'''
#define BUILD_PROVIDER
#include "abi.h"
extern "C" NOINLINE U provider_scalar(int8_t a, uint16_t b, U c, double d, U tail,
                                      Effects *e) noexcept {
  U r = U(int64_t(a) * 19 + b) + ROT(c, 11) + U(d * 8) + tail * 23;
  e->value ^= r;
  ++e->calls;
  return r;
}
extern "C" NOINLINE S8 provider_small(S8 s, U salt, Effects *e) noexcept {
  U r = (ROT(s.value, 7) ^ salt) + 0x123456789ULL;
  e->value += r;
  ++e->calls;
  return S8{r};
}
extern "C" NOINLINE S24 provider_big(S24 s, Effects *e) noexcept {
  ++e->calls;
  e->value ^= s.a + s.b + s.c;
  return S24{s.c + 17, ROT(s.a, 9), s.b ^ 0x987654321ULL};
}
extern "C" NOINLINE void provider_pointer(const S24 *in, S24 *out, Effects *e) noexcept {
  out->a = in->c + 17;
  out->b = ROT(in->a, 9);
  out->c = in->b ^ 0x987654321ULL;
  e->value ^= out->a + out->b + out->c;
  ++e->calls;
}
extern "C" NOINLINE int provider_throw(int x, Effects *e) {
  e->value += U(uint32_t(x));
  ++e->calls;
  if (x < 0) throw int(x ^ 0x1357);
  return x * 5 + 9;
}
'''

POSITIVE_SOURCE = r'''
#define BUILD_PROTECTED
#include "abi.h"
extern "C" NOINLINE U abi_param8(S8 s, Effects *e) noexcept {
  U r = ROT(s.value, 13) + 0x31415926ULL;
  e->value ^= r;
  return r;
}
extern "C" NOINLINE U abi_param16(S16 s, Effects *e) noexcept {
  U r = s.a * 3 + ROT(s.b, 17);
  e->value += r;
  return r;
}
extern "C" NOINLINE U abi_param24(S24 s, Effects *e) noexcept {
  U r = ROT(s.a, 5) + s.b * 7 + (s.c ^ 0xabcdefULL);
  e->value ^= r;
  return r;
}
extern "C" NOINLINE U abi_packed(Packed s, Effects *e) noexcept {
  U r = s.value + U(s.tag) * 31 + U(s.tail) * 43;
  e->value += r;
  return r;
}
extern "C" NOINLINE U abi_nontrivial(NonTrivial s, Effects *e) noexcept {
  U r = s.value * 17 + 5;
  e->value ^= r;
  return r;
}
extern "C" NOINLINE double abi_floats(Floats s, Effects *e) noexcept {
  double r = double(s.a) + double(s.b);
  e->value += U(r);
  return r;
}
extern "C" NOINLINE S8 abi_return8(U x, Effects *e) noexcept {
  S8 s{ROT(x, 21) ^ 0xfedcba9876543210ULL};
  e->value ^= s.value;
  return s;
}
extern "C" NOINLINE U abi_stack(S8 s, U a, U b, U c, U d, U f, Effects *e) noexcept {
  U r = ROT(s.value, 13) + a * 3 + b * 5 + c * 7 + d * 11 + f * 17;
  e->value += r;
  return r;
}
extern "C" NOINLINE U abi_import_scalar(int8_t a, uint16_t b, U c, double d,
                                        U tail, Effects *e) noexcept {
  return provider_scalar(a, b, c, d, tail, e) + tail * 7;
}
extern "C" NOINLINE U abi_callback_scalar(ScalarCB cb, int8_t a, uint16_t b, U c,
                                          double d, U tail, Effects *e) noexcept {
  return cb(a, b, c, d, tail, e) ^ (c + tail);
}
extern "C" NOINLINE U abi_import_small(S8 s, U salt, Effects *e) noexcept {
  S8 r = provider_small(s, salt, e);
  return ROT(r.value, 19) + salt;
}
extern "C" NOINLINE U abi_callback_small(SmallCB cb, S8 s, U salt, Effects *e) noexcept {
  S8 r = cb(s, salt, e);
  return ROT(r.value, 19) ^ salt;
}
extern "C" NOINLINE U abi_pointer_import(const S24 *in, S24 *out, Effects *e) noexcept {
  provider_pointer(in, out, e);
  return out->a + out->b * 3 + out->c * 5;
}
extern "C" NOINLINE int abi_throw_import(int x, Effects *e) {
  return provider_throw(x, e) + 3;
}
extern "C" NOINLINE int abi_throw_callback(ThrowCB cb, int x, Effects *e) {
  return cb(x, e) + 7;
}
extern "C" NOINLINE U abi_address(U x, Effects *e) noexcept {
  U r = ROT(x, 3) + 0x7654321;
  e->value += r;
  return r;
}
extern "C" NOINLINE AddressCB abi_get_address() noexcept { return &abi_address; }
struct LocalGuard {
  Effects *e;
  NOINLINE ~LocalGuard() noexcept { ++e->cleanups; }
};
extern "C" NOINLINE int abi_cleanup_import(int x, Effects *e) {
  LocalGuard guard{e};
  return provider_throw(x, e) + 13;
}
extern "C" NOINLINE int abi_cleanup_callback(ThrowCB cb, int x, Effects *e) {
  LocalGuard guard{e};
  return cb(x, e) + 17;
}
extern "C" NOINLINE int abi_eh(int x, Effects *e) {
  try {
    LocalGuard guard{e};
    return provider_throw(x, e) + 11;
  } catch (int payload) {
    return payload ^ 0x2468;
  }
}
static U startup_value;
struct Initialization {
  NOINLINE Initialization() noexcept { startup_value = 0x6172697374617274ULL; }
};
static Initialization initialization;
extern "C" NOINLINE U abi_startup() noexcept { return startup_value; }
'''

CONTROL_SOURCES = {
    "abi_return16": r'''
extern "C" NOINLINE S16 abi_return16(U x, Effects *e) noexcept {
  e->value += x;
  return S16{x + 17, ROT(x, 9)};
}
''',
    "abi_return24": r'''
extern "C" NOINLINE S24 abi_return24(U x, Effects *e) noexcept {
  e->value ^= x;
  return S24{x + 19, ROT(x, 11), x ^ 0x456789ULL};
}
''',
    "abi_big_import": r'''
extern "C" NOINLINE U abi_big_import(S24 s, Effects *e) noexcept {
  S24 r = provider_big(s, e);
  return r.a + r.b * 3 + r.c * 5;
}
''',
    "abi_big_callback": r'''
extern "C" NOINLINE U abi_big_callback(BigCB cb, S24 s, Effects *e) noexcept {
  S24 r = cb(s, e);
  return r.a + r.b * 7 + r.c * 11;
}
''',
    "abi_incoming": r'''
extern "C" NOINLINE int abi_incoming(int x, Effects *e) {
  return provider_throw(x, e) + 3;
}
extern "C" NOINLINE int abi_incoming_caller(int x, Effects *e) {
  try { return abi_incoming(x, e) + 13; }
  catch (int payload) { return payload ^ 0x4567; }
}
''',
}

CONSUMER_SOURCE = r'''
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "abi.h"
static void check(bool ok, const char *what) {
  if (!ok) { fprintf(stderr, "C++ DLL ABI failure: %s\n", what); exit(1); }
}
static U rotate(U x, unsigned n) { return (x >> (64 - n)) + (x << n); }
static void effects(const Effects &e, U value, unsigned calls = 0, unsigned cleanups = 0) {
  check(e.value == value && e.calls == calls && e.cleanups == cleanups, "effects");
}
static void exports(HMODULE module, const char *const *expected, unsigned count) {
  const unsigned char *base = reinterpret_cast<const unsigned char *>(module);
  const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
  check(dos->e_magic == IMAGE_DOS_SIGNATURE, "PE DOS header");
  const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(base + dos->e_lfanew);
  check(nt->Signature == IMAGE_NT_SIGNATURE && nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64,
        "Windows x64 PE header");
  auto directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  check(directory.VirtualAddress != 0, "export directory");
  const auto *table = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(base + directory.VirtualAddress);
  check(table->NumberOfNames == count && table->NumberOfFunctions == count, "public export count/helpers");
  const auto *names = reinterpret_cast<const DWORD *>(base + table->AddressOfNames);
  const auto *ordinals = reinterpret_cast<const WORD *>(base + table->AddressOfNameOrdinals);
  const auto *addresses = reinterpret_cast<const DWORD *>(base + table->AddressOfFunctions);
  U seen = 0, seen_ordinals = 0;
  for (unsigned i = 0; i < count; ++i) {
    const char *name = reinterpret_cast<const char *>(base + names[i]);
    unsigned j = 0;
    while (j < count && strcmp(name, expected[j]) != 0) ++j;
    check(j < count && !(seen & (U(1) << j)), "unexpected/duplicate public export");
    unsigned ordinal = ordinals[i];
    check(ordinal < count && !(seen_ordinals & (U(1) << ordinal)), "duplicate export ordinal");
    DWORD address = addresses[ordinal];
    check(address && !(address >= directory.VirtualAddress &&
                       address - directory.VirtualAddress < directory.Size), "missing/forwarded public export");
    check(GetProcAddress(module, name) == reinterpret_cast<FARPROC>(const_cast<unsigned char *>(base + address)),
          "export address");
    seen |= U(1) << j;
    seen_ordinals |= U(1) << ordinal;
  }
}
static NOINLINE U scalar_callback(int8_t a, uint16_t b, U c, double d, U tail,
                                  Effects *e) noexcept {
  U r = U(int64_t(a) * 29 + b) + rotate(c, 15) + U(d * 4) + tail * 31;
  e->value += r;
  ++e->calls;
  return r;
}
static NOINLINE S8 small_callback(S8 s, U salt, Effects *e) noexcept {
  U r = rotate(s.value, 23) + salt * 13;
  e->value ^= r;
  ++e->calls;
  return S8{r};
}
static NOINLINE S24 big_callback(S24 s, Effects *e) noexcept {
  ++e->calls;
  e->value += s.a + s.b + s.c;
  return S24{s.c * 3, rotate(s.b, 13), s.a + 31};
}
static NOINLINE int throw_callback(int x, Effects *e) {
  e->value += U(uint32_t(x)) * 3;
  ++e->calls;
  if (x < 0) throw int(x ^ 0x3579);
  return x * 7 + 19;
}
struct HostGuard {
  unsigned *cleanups;
  NOINLINE ~HostGuard() noexcept { ++*cleanups; }
};
#ifdef CONTROLS
#define ENTRIES(X) \
  X(abi_return16) X(abi_return24) X(abi_big_import) X(abi_big_callback) \
  X(abi_incoming) X(abi_incoming_caller)
#else
#define ENTRIES(X) \
  X(abi_param8) X(abi_param16) X(abi_param24) X(abi_packed) X(abi_nontrivial) \
  X(abi_floats) X(abi_return8) X(abi_stack) X(abi_import_scalar) X(abi_callback_scalar) \
  X(abi_import_small) X(abi_callback_small) X(abi_pointer_import) X(abi_throw_import) \
  X(abi_throw_callback) X(abi_address) X(abi_get_address) X(abi_eh) \
  X(abi_cleanup_import) X(abi_cleanup_callback) X(abi_startup)
#endif
struct Interface {
#define FIELD(name) decltype(&::name) name;
  ENTRIES(FIELD)
#undef FIELD
};
static Interface imported() {
  Interface api{};
#define ASSIGN(name) api.name = &name;
  ENTRIES(ASSIGN)
#undef ASSIGN
  return api;
}
static Interface dynamic(HMODULE module) {
  Interface api{};
#define ASSIGN(name) api.name = reinterpret_cast<decltype(api.name)>(GetProcAddress(module, #name)); \
                     check(api.name != nullptr, #name);
  ENTRIES(ASSIGN)
#undef ASSIGN
  return api;
}
static void exercise(const Interface &api) {
  const U start = 0x123456789abcdef0ULL;
#ifdef CONTROLS
  const U x = 0x8123456789abcdefULL;
  Effects e{start, 0, 0};
  S16 r16 = api.abi_return16(x, &e);
  check(r16.a == x + 17 && r16.b == rotate(x, 9), "S16 sret native control");
  effects(e, start + x);
  e = {start, 0, 0};
  S24 r24 = api.abi_return24(x, &e);
  check(r24.a == x + 19 && r24.b == rotate(x, 11) && r24.c == (x ^ 0x456789ULL),
        "S24 sret native control");
  effects(e, start ^ x);
  S24 s{x, 0x9123abcdef456789ULL, 0xa234567890abcdefULL};
  e = {start, 0, 0};
  U a = s.c + 17, b = rotate(s.a, 9), c = s.b ^ 0x987654321ULL;
  check(api.abi_big_import(s, &e) == a + b * 3 + c * 5, "escaping import native control");
  effects(e, start ^ (s.a + s.b + s.c), 1);
  e = {start, 0, 0};
  check(api.abi_big_callback(big_callback, s, &e) == s.c * 3 + rotate(s.b, 13) * 7 + (s.a + 31) * 11,
        "escaping callback native control");
  effects(e, start + s.a + s.b + s.c, 1);
  const int exception_inputs[] = {17, -37, -1009};
  for (int x : exception_inputs) {
    e = {start, 0, 0};
    int expected = x < 0 ? ((x ^ 0x1357) ^ 0x4567) : x * 5 + 25;
    check(api.abi_incoming_caller(x, &e) == expected, "same-module incoming invoke control");
    effects(e, start + U(uint32_t(x)), 1);
  }
#else
  check(api.abi_startup() == 0x6172697374617274ULL, "normal CRT DLL startup");
  for (unsigned i = 0; i < 3; ++i) {
    U x = 0x8123456789abcdefULL + i * 0x11223344556677ULL;
    Effects e{start, 0, 0};
    S8 s8{x};
    U r = rotate(x, 13) + 0x31415926ULL;
    check(api.abi_param8(s8, &e) == r && s8.value == x, "S8 parameter/external indirect entry");
    effects(e, start ^ r);
    S16 s16{x, x ^ 0x923456789abcdef0ULL};
    e = {start, 0, 0};
    r = s16.a * 3 + rotate(s16.b, 17);
    check(api.abi_param16(s16, &e) == r && s16.a == x, "S16 parameter");
    effects(e, start + r);
    S24 s24{x, x ^ 0xa23456789abcdef0ULL, x + 0x3456789ULL};
    e = {start, 0, 0};
    r = rotate(s24.a, 5) + s24.b * 7 + (s24.c ^ 0xabcdefULL);
    check(api.abi_param24(s24, &e) == r && s24.a == x, "S24 parameter/field 2");
    effects(e, start ^ r);
    Packed packed{static_cast<unsigned char>(241 - i), x, static_cast<uint16_t>(0xf123 + i)};
    e = {start, 0, 0};
    r = x + U(packed.tag) * 31 + U(packed.tail) * 43;
    check(api.abi_packed(packed, &e) == r && packed.value == x, "packed parameter");
    effects(e, start + r);
    Counts counts{};
    e = {start, 0, 0};
    {
      NonTrivial original(x, &counts);
      r = (x + 9) * 17 + 5;
      check(api.abi_nontrivial(original, &e) == r && original.value == x, "nontrivial parameter value");
      check(counts.constructed == 1 && counts.copied == 1 && counts.destroyed == 1 &&
            counts.destruction_sum == x + 9, "nontrivial parameter copy/destruction");
      effects(e, start ^ r);
    }
    check(counts.constructed == 1 && counts.copied == 1 && counts.destroyed == 2 &&
          counts.destruction_sum == x + (x + 9), "nontrivial original destruction");
    Floats f{float(i) + 1.25f, float(i) + 2.5f};
    e = {start, 0, 0};
    double expected_float = 3.75 + i * 2;
    check(api.abi_floats(f, &e) == expected_float, "float aggregate");
    effects(e, start + U(expected_float));
    e = {start, 0, 0};
    S8 returned = api.abi_return8(x, &e);
    r = rotate(x, 21) ^ 0xfedcba9876543210ULL;
    check(returned.value == r, "8-byte aggregate return");
    effects(e, start ^ r);
    e = {start, 0, 0};
    r = rotate(x, 13) + 17 * 3 + 29 * 5 + 43 * 7 + 59 * 11 + 71 * 17;
    check(api.abi_stack(s8, 17, 29, 43, 59, 71, &e) == r, "extra stack arguments");
    effects(e, start + r);
    const int8_t narrow_signed = -97;
    const uint16_t narrow_unsigned = 60013;
    const U tail = 0xe123456789abcdefULL + i;
    e = {start, 0, 0};
    r = U(int64_t(narrow_signed) * 19 + narrow_unsigned) + rotate(x, 11) + 28 + tail * 23;
    check(api.abi_import_scalar(narrow_signed, narrow_unsigned, x, 3.5, tail, &e) == r + tail * 7,
          "scalar import/extension/stack arguments");
    effects(e, start ^ r, 1);
    e = {start, 0, 0};
    r = U(int64_t(narrow_signed) * 29 + narrow_unsigned) + rotate(x, 15) + 14 + tail * 31;
    check(api.abi_callback_scalar(scalar_callback, narrow_signed, narrow_unsigned, x, 3.5, tail, &e) ==
          (r ^ (x + tail)), "scalar callback");
    effects(e, start + r, 1);
    e = {start, 0, 0};
    r = (rotate(x, 7) ^ tail) + 0x123456789ULL;
    check(api.abi_import_small(s8, tail, &e) == rotate(r, 19) + tail, "small aggregate import");
    effects(e, start + r, 1);
    e = {start, 0, 0};
    r = rotate(x, 23) + tail * 13;
    check(api.abi_callback_small(small_callback, s8, tail, &e) == (rotate(r, 19) ^ tail),
          "small aggregate callback");
    effects(e, start ^ r, 1);
    S24 out{};
    e = {start, 0, 0};
    U a = s24.c + 17, b = rotate(s24.a, 9), c = s24.b ^ 0x987654321ULL;
    check(api.abi_pointer_import(&s24, &out, &e) == a + b * 3 + c * 5 &&
          out.a == a && out.b == b && out.c == c && s24.a == x, "pointer aggregate import control");
    effects(e, start ^ (a + b + c), 1);
    e = {start, 0, 0};
    r = rotate(x, 3) + 0x7654321;
    AddressCB address = api.abi_get_address();
    check(address == api.abi_address && address(x, &e) == r, "address-taken policy control");
    effects(e, start + r);
  }
  const int exception_inputs[] = {17, -37, -1009};
  for (int x : exception_inputs) {
    for (unsigned mode = 0; mode < 4; ++mode) {
      bool callback = (mode & 1) != 0;
      bool dll_cleanup = mode >= 2;
      Effects e{start, 0, 0};
      unsigned cleanups = 0;
      bool caught = false;
      int result = 0;
      try {
        HostGuard guard{&cleanups};
        if (dll_cleanup)
          result = callback ? api.abi_cleanup_callback(throw_callback, x, &e) : api.abi_cleanup_import(x, &e);
        else
          result = callback ? api.abi_throw_callback(throw_callback, x, &e) : api.abi_throw_import(x, &e);
      } catch (int payload) {
        caught = true;
        check(payload == (x ^ (callback ? 0x3579 : 0x1357)), "exact int exception payload");
        check(cleanups == 1, "host RAII cleanup before catch");
      } catch (...) { check(false, "exception type changed"); }
      check(caught == (x < 0) && cleanups == 1, "throw propagation/host RAII count");
      if (x >= 0) {
        int expected = callback ? x * 7 + (dll_cleanup ? 36 : 26) : x * 5 + (dll_cleanup ? 22 : 12);
        check(result == expected, "throw relay success path");
      }
      effects(e, start + U(uint32_t(x)) * (callback ? 3 : 1), 1, dll_cleanup ? 1 : 0);
    }
    Effects e{start, 0, 0};
    int expected = x < 0 ? ((x ^ 0x1357) ^ 0x2468) : x * 5 + 20;
    check(api.abi_eh(x, &e) == expected, "local EH policy control");
    effects(e, start + U(uint32_t(x)), 1, 1);
  }
#endif
}
int main(int argc, char **argv) {
  check(argc == 2, "DLL path argument");
  HMODULE module = LoadLibraryA(argv[1]);
  check(module != nullptr, "LoadLibrary");
#define NAME(name) #name,
  const char *const names[] = {ENTRIES(NAME)};
#undef NAME
  exports(module, names, unsigned(sizeof(names) / sizeof(names[0])));
  exercise(imported());
  exercise(dynamic(module));
  check(FreeLibrary(module) != 0, "FreeLibrary");
#ifdef CONTROLS
  puts("CPP_DLL_CONTROLS_OK imports=1 indirect=1 sret=1 escaping=1 incoming=1");
#else
  puts("CPP_DLL_ABI_OK imports=1 indirect=1 aggregates=1 copies=1 effects=1 exceptions=1 cleanup=1 exports=1 startup=1");
#endif
}
'''


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(command, work, *, report=None, succeeds=True):
    env = os.environ.copy()
    for key in ("OBF_CONFIG", "OBF_ENABLE", "OBF_SEED", "OBF_COVERAGE_REPORT", "OBF_LTO_MODE", "OBF_LTO_INPUTS_VALIDATED"):
        env.pop(key, None)
    env["PATH"] = str(work) + os.pathsep + env.get("PATH", "")
    if report is not None:
        env["OBF_COVERAGE_REPORT"] = str(report)
    result = subprocess.run([str(value) for value in command], cwd=work, env=env,
                            capture_output=True, text=True, timeout=300)
    with (work / "commands.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"command": [str(value) for value in command],
                                 "exit": result.returncode, "stdout": result.stdout,
                                 "stderr": result.stderr, "report": str(report) if report else None}) + "\n")
    require((result.returncode == 0) == succeeds,
            f"unexpected exit {result.returncode}: {command!r}\n{result.stdout}\n{result.stderr}")
    return result


def policy(path, names, level):
    lines = ["seed: 8675309", "default_level: none", "targets:"]
    for name in names:
        lines += [f"  - match: {name}", f"    level: {level}"]
    lines += ["vm:", "  max_mba_depth: 0", "security:", "  fail_on_public_obf_symbol: true"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def coverage(path):
    require(path.is_file(), f"missing compiler coverage report: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    require(data.get("evidence") == "compiler_report" and data.get("capture") == "enabled",
            f"missing compiler-report evidence: {path}")
    return data


def selected(data, name):
    entries = [event["policy"] for event in data["requested_policy"]
               if event["owner"] == name and event["phase"] == "selected"]
    require(len(entries) == 1, f"missing/ambiguous selected policy for {name}")
    return entries[0]


def events(data, stage, name, mechanism):
    return [event for event in data[stage]
            if event["owner"] == name and event["mechanism"] == mechanism]


def vm_emitted(data, name):
    return any(event["status"] == "emitted" for event in events(data, "emission", name, "vm"))


def check_positive(data, level):
    for name in VM_EXPORTS:
        choice = selected(data, name)
        require(choice["allow_vm"] and choice["level"] == level, f"lost VM policy for {name}")
        require(any(event["status"] == "admitted" for event in events(data, "admission", name, "vm")),
                f"supported ABI path not admitted: {name}")
        require(vm_emitted(data, name), f"supported ABI path did not emit VM: {name}")
    for name, expected_level in EXCLUDED_EXPORTS.items():
        choice = selected(data, name)
        require(not choice["allow_vm"] and choice["level"] == expected_level,
                f"lost address-taking/local-EH policy exclusion: {name}")
        category = "address-taken" if name == "abi_address" else "risky features"
        require(choice["source"] == "config_rule" and name in choice["detail"] and category in choice["detail"],
                f"wrong source/category for policy exclusion: {name}")
        require(not events(data, "admission", name, "vm") and not vm_emitted(data, name),
                f"policy-excluded control unexpectedly reached VM: {name}")
    require(any(event["mechanism"] == "security_gates" and event["status"] == "validated"
                for event in data["finalization"]), "compiler security gates not validated")


def check_control(data, name, kind, strict):
    choice = selected(data, name)
    require(choice["allow_vm"] and choice["level"] == ("strong_vm" if strict else "vm"),
            f"negative/control policy became an exclusion: {name}")
    if kind == "incoming_invoke":
        incoming = events(data, "admission", name, "vm_incoming_site")
        require(any(event["status"] == ("rejected" if strict else "preserved") for event in incoming),
                f"incoming invoke restriction not observed: {name}")
        require(vm_emitted(data, name) == (not strict), f"wrong incoming invoke emission state: {name}")
    else:
        admission = events(data, "admission", name, "vm")
        require(any(event["status"] == ("rejected" if kind == "boundary" and strict else "skipped")
                    for event in admission), f"missing semantic ABI rejection/skip: {name}")
        require(not vm_emitted(data, name), f"unsupported ABI path emitted VM: {name}")
        if kind == "escaping_alloca":
            require(any("alloca" in event["reason"] for event in admission),
                    f"escaping aggregate buffer not identified as unsupported: {name}")
    if kind == "escaping_alloca" and strict:
        require(any(event["mechanism"] == "security_gates" and event["status"] == "rejected"
                    for event in data["finalization"]), "mandatory VM invariant did not reject escaping buffer")


def build(args, work, folder, source, names, level, optimization, *, succeeds=True):
    config = folder / "policy.yaml"
    report = folder / "coverage.json"
    obj = folder / "module.obj"
    policy(config, names, level)
    result = run([args.wrapper, *CXX_FLAGS, f"-O{optimization}", f"--obf-config={config}",
                  "-c", source, "-o", obj], work, report=report, succeeds=succeeds)
    data = coverage(report)
    if not succeeds:
        return data, result
    dll = folder / ("abi-controls.dll" if level == "vm" and names == tuple(CONTROL_CASES) else "abi-protected.dll")
    # Do not use -nostdlib, /entry or /nodefaultlib: normal CRT startup and the
    # wrapper's configured runtime/checksum binder are part of the ABI fixture.
    run([args.wrapper, "-fms-runtime-lib=dll", "-shared", "-fuse-ld=lld", obj,
         work / "abi-provider.lib", f"-Wl,/map:{folder / 'module.map'}", "-o", dll], work)
    return data, dll


def consumer(args, work, folder, dll, *, controls=False):
    cache = work / ("controls-consumer.exe" if controls else "consumer.exe")
    if not cache.exists():
        command = [args.clang, "--driver-mode=g++", *CXX_FLAGS, "-O2", "-fuse-ld=lld"]
        if controls:
            command.append("-DCONTROLS")
        run([*command, work / "consumer.cpp", dll.with_suffix(".lib"), "-o", cache], work)
    executable = folder / "consumer.exe"
    shutil.copyfile(cache, executable)
    result = run([executable, dll], work)
    print(result.stdout, end="", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wrapper", required=True, help="configured obf-clang++ launcher")
    parser.add_argument("--clang", required=True, help="configured canonical Clang (g++ mode is explicit)")
    parser.add_argument("--work", required=True, help="parent for the isolated, retained evidence directory")
    args = parser.parse_args()
    require(os.name == "nt", "this regression requires native Windows x64")
    parent = Path(args.work).resolve()
    parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="cpp-dll-abi-", dir=parent))
    print(f"CPP_DLL_ABI_WORK {work}", flush=True)
    (work / "abi.h").write_text(HEADER, encoding="utf-8")
    (work / "provider.cpp").write_text(PROVIDER_SOURCE, encoding="utf-8")
    (work / "positive.cpp").write_text(POSITIVE_SOURCE, encoding="utf-8")
    (work / "consumer.cpp").write_text(CONSUMER_SOURCE, encoding="utf-8")
    prefix = '#define BUILD_PROTECTED\n#include "abi.h"\n'
    (work / "controls.cpp").write_text(prefix + "\n".join(CONTROL_SOURCES.values()), encoding="utf-8")
    for name, source in CONTROL_SOURCES.items():
        (work / f"{name}.cpp").write_text(prefix + source, encoding="utf-8")
    run([args.clang, "--driver-mode=g++", *CXX_FLAGS, "-O2", "-shared", "-fuse-ld=lld",
         work / "provider.cpp", "-o", work / "abi-provider.dll"], work)
    for optimization in (0, 2):
        for level in ("vm", "strong_vm"):
            folder = work / f"positive-{level}-o{optimization}"
            folder.mkdir()
            data, dll = build(args, work, folder, work / "positive.cpp",
                              (*VM_EXPORTS, *EXCLUDED_EXPORTS), level, optimization)
            check_positive(data, level)
            consumer(args, work, folder, dll)
            print(f"CPP_DLL_ABI_PASS O{optimization} {level} native=checked emission=compiler_report "
                  "address_taken=excluded local_eh=excluded cleanup_import=excluded cleanup_callback=excluded",
                  flush=True)
        folder = work / f"controls-vm-o{optimization}"
        folder.mkdir()
        data, dll = build(args, work, folder, work / "controls.cpp", tuple(CONTROL_CASES), "vm", optimization)
        for name, kind in CONTROL_CASES.items():
            check_control(data, name, kind, False)
        consumer(args, work, folder, dll, controls=True)
        print(f"CPP_DLL_ABI_CONTROL O{optimization} vm best_effort=checked incoming=preserved", flush=True)
        for name, kind in CONTROL_CASES.items():
            folder = work / f"reject-{name}-strong_vm-o{optimization}"
            folder.mkdir()
            data, result = build(args, work, folder, work / f"{name}.cpp", (name,),
                                 "strong_vm", optimization, succeeds=False)
            check_control(data, name, kind, True)
            # Stable fatal categories corroborate the semantic report states;
            # reject a tool/link failure rather than accepting arbitrary errors.
            category = "strong_vm invariant violation" if kind == "escaping_alloca" else "vm strict boundary violation"
            require(category in result.stderr, f"wrong strict rejection category for {name}: {result.stderr}")
        print(f"CPP_DLL_ABI_REJECTIONS O{optimization} strong_vm sret16=1 sret24=1 "
              "escaping_import=1 escaping_callback=1 incoming_invoke=1", flush=True)
    print("CPP_DLL_ABI_COMPLETE native_abi=checked vm_execution=requires_independent_trace", flush=True)


if __name__ == "__main__":
    main()
