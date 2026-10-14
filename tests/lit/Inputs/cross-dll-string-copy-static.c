#include <stdint.h>

#if defined(COPY_DLL_EXPORT)
#define DATA_API __declspec(dllexport)
#else
#define DATA_API
#endif

#if defined(COPY_STATIC_NUMERIC_PROVIDER)
DATA_API const unsigned char foreign_copy_text[] = {7, 111, 91};
#elif defined(COPY_STATIC_PROVIDER)
DATA_API const unsigned char foreign_copy_text[] = "foreign static plaintext";
#elif defined(COPY_STATIC_READER)
#if defined(COPY_DLL_IMPORT)
// Name the actual COFF IAT pointer cell. A VM static-address table can retain
// this link-resolvable symbol without asking the linker for the array's
// non-import spelling. This is still a one-level foreign static dependency,
// not a caller-owned pointer or an ownership exemption.
extern const unsigned char *const __imp_foreign_copy_text;
#define foreign_copy_text __imp_foreign_copy_text
#else
extern const unsigned char foreign_copy_text[];
#endif
uint64_t exchange_static_read(uint64_t index, uint64_t *effect) {
  uint64_t value = foreign_copy_text[index];
  *effect = value;
  return value;
}
#else
uint64_t exchange_static_read(uint64_t index, uint64_t *effect);
int main(void) {
  uint64_t effect = UINT64_C(0xdeadbeef);
  return exchange_static_read(1, &effect) != (uint64_t)'o' ||
         effect != (uint64_t)'o';
}
#endif
