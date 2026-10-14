#include <stdint.h>

#if defined(COPY_DLL_EXPORT)
#define DATA_API __declspec(dllexport)
#elif defined(COPY_DLL_IMPORT)
#define DATA_API __declspec(dllimport)
#else
#define DATA_API
#endif

#if defined(COPY_STATIC_NUMERIC_PROVIDER)
DATA_API const unsigned char foreign_copy_text[] = {7, 111, 91};
#elif defined(COPY_STATIC_PROVIDER)
DATA_API const unsigned char foreign_copy_text[] = "foreign static plaintext";
#elif defined(COPY_STATIC_READER)
extern DATA_API const unsigned char foreign_copy_text[];
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
