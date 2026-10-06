#ifdef AUDIT_OTHER_DIRECT
#define audit_direct audit_other_direct
#endif
#include "ownership.h"
#ifdef AUDIT_WEAK
#define AUDIT_DEFINITION __attribute__((weak))
#else
#define AUDIT_DEFINITION
#endif
#if AUDIT_KIND == 0 || AUDIT_KIND == 9
#ifdef AUDIT_LOCAL_DIRECT
#define AUDIT_DIRECT_LINKAGE static
#else
#define AUDIT_DIRECT_LINKAGE extern
#endif
#ifdef AUDIT_BINARY
AUDIT_DEFINITION AUDIT_DIRECT_LINKAGE const unsigned char audit_direct[4] = {110, 78, 12, 13};
#else
AUDIT_DEFINITION AUDIT_DIRECT_LINKAGE const unsigned char audit_direct[4] = "nST";
#endif
#elif AUDIT_KIND == 1 || AUDIT_KIND == 2
#ifndef AUDIT_CELL_LEAF_SYMBOL
#define AUDIT_CELL_LEAF_SYMBOL "audit_secret"
#endif
static const char audit_secret[] __asm__(AUDIT_CELL_LEAF_SYMBOL) = "nATIVE_CROSS_OBJECT_SECRET_20261005_Q9OP";
#if AUDIT_KIND == 1
AUDIT_DEFINITION extern const char * const audit_cell = audit_secret;
#else
static const char audit_second[] __asm__("audit_second") = "SECOND_CROSS_OBJECT_SECRET_Q9OP";
AUDIT_DEFINITION extern const char * const audit_table[2] = {audit_secret, audit_second};
#endif
#elif AUDIT_KIND == 3
AUDIT_DEFINITION extern const uint32_t audit_integers[2] = {110, 78};
#elif AUDIT_KIND == 4
extern const uint32_t audit_unused_integers[2] = {31, 47};
static const char audit_unused_secret[] = "UNEXTRACTED_NATIVE_STRING";
extern const char * const audit_unused_cell = audit_unused_secret;
#elif AUDIT_KIND == 5 || AUDIT_KIND == 6
#ifndef AUDIT_INTEGER_LEAF_SYMBOL
#define AUDIT_INTEGER_LEAF_SYMBOL "audit_leaf_numbers"
#endif
static const uint32_t audit_leaf_numbers[2] __asm__(AUDIT_INTEGER_LEAF_SYMBOL) = {110, 78};
#if AUDIT_KIND == 5
extern const uint32_t * const audit_integer_cell = audit_leaf_numbers;
#else
static const uint32_t * const audit_integer_cell __asm__("audit_integer_cell") = audit_leaf_numbers;
extern const uint32_t * const * const audit_integer_chain = &audit_integer_cell;
#endif
#endif
#ifdef AUDIT_FORCE
unsigned audit_force(void) { return 0; }
#endif
#ifdef AUDIT_PULL_FORCE
unsigned audit_pull_force(void) { return audit_force(); }
#endif
#ifdef AUDIT_BAD_RECORD
#if defined(_WIN32)
#pragma section(".obfns", read)
__declspec(allocate(".obfns")) __attribute__((used))
#else
__attribute__((section(".obfns"), used))
#endif
static const unsigned char audit_bad_record[] = {'O', 'B', 'N', 'S', 1};
#endif
