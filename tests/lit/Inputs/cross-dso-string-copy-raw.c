#include "cross-dso-string-copy-api.h"

#include <string.h>

#if COPY_VARIANT == 1
static const char raw_primary[] = "amber producer A owns this copy";
#define COPY_SECONDARY "A: independent data 1847"
#elif COPY_VARIANT == 2
static const char raw_primary[] = "violet producer B has another payload";
#define COPY_SECONDARY "B: distinct data 9263"
#else
#error COPY_VARIANT must be 1 or 2
#endif
static const char raw_empty[] = "";

#ifdef COPY_V2_ONLY
#define exchange_copy_v1 exchange_copy_v2
#endif

extern "C" __attribute__((visibility("default")))
int exchange_copy_v1(uint32_t id, char *destination, size_t capacity,
                     size_t *required) {
  static const char raw_secondary[] = COPY_SECONDARY;
  const char *text;
  size_t length;
  if (required == NULL)
    return COPY_INVALID_ARGUMENT;
  switch (id) {
  case 1:
    text = raw_primary;
    length = sizeof(raw_primary);
    break;
  case 2:
    text = raw_secondary;
    length = sizeof(raw_secondary);
    break;
  case 3:
    text = raw_empty;
    length = sizeof(raw_empty);
    break;
  default:
    *required = 0;
    return COPY_UNKNOWN_ID;
  }
  *required = length;
  if (destination == NULL)
    return capacity == 0 ? COPY_NEED_CAPACITY : COPY_INVALID_ARGUMENT;
  if (capacity < length)
    return COPY_NEED_CAPACITY;
  memcpy(destination, text, length);
  return COPY_OK;
}
