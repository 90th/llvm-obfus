#include <obf/string_copy.h>

#if COPY_BAD_CASE == 1
OBF_STRING_COPY_SOURCE_V1(exchange_copy_v1, 1)
static char invalid_source[] = "mutable producer source";
#elif COPY_BAD_CASE == 2
OBF_STRING_COPY_SOURCE_V1(exchange_copy_v1, 1)
static const char first_source[] = "duplicate first source";
OBF_STRING_COPY_SOURCE_V1(exchange_copy_v1, 1)
static const char second_source[] = "duplicate second source";
#elif COPY_BAD_CASE == 3
OBF_STRING_COPY_SOURCE_V1(exchange_copy_v1, 1)
static const char invalid_source[] = "embedded\0producer source";
#elif COPY_BAD_CASE == 6
OBF_STRING_COPY_SOURCE_V1(exchange_copy_v1, 1)
const char invalid_source[] = "external producer source";
#elif COPY_BAD_CASE == 7
OBF_STRING_COPY_SOURCE_V1(exchange_copy_v1, 1)
static _Thread_local const char invalid_source[] = "TLS producer source";
#elif COPY_BAD_CASE == 8
OBF_STRING_COPY_SOURCE_V1(exchange_copy_v1, 1)
static const char invalid_source[64] = "padded producer source";
#elif COPY_BAD_CASE == 9
OBF_STRING_COPY_SOURCE_V1(exchange_copy, 1)
static const char invalid_source[] = "unversioned producer source";
#elif COPY_BAD_CASE == 10
OBF_STRING_COPY_SOURCE_V1(exchange_copy_v1, 1)
static const char invalid_source[] = "unsupported shared producer source";
const char *exchange_borrow(void) { return invalid_source; }
#else
OBF_STRING_COPY_SOURCE_V1(exchange_copy_v1, 1)
static const char invalid_source[] = "invalid API producer source";
#endif

#if COPY_BAD_CASE == 4
int exchange_copy_v1(uint32_t id, char *destination, uint32_t capacity,
                     size_t *required);
__attribute__((used)) static void *keep_bad_declaration = (void *)&exchange_copy_v1;
#elif COPY_BAD_CASE == 5
OBF_STRING_COPY_DECLARE_V1(exchange_copy_v1);
int exchange_copy_v1(uint32_t id, char *destination, size_t capacity,
                     size_t *required) {
  (void)id;
  (void)destination;
  (void)capacity;
  (void)required;
  return 0;
}
#elif COPY_BAD_CASE == 9
int exchange_copy(uint32_t id, char *destination, size_t capacity,
                  size_t *required);
#else
OBF_STRING_COPY_DECLARE_V1(exchange_copy_v1);
#endif

unsigned exchange_anchor(unsigned value) { return value + 1; }
