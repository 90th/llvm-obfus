#include <obf/string_copy.h>

#if COPY_VARIANT == 1
OBF_STRING_COPY_SOURCE_V1(exchange_copy_v1, 1)
static const char copy_primary[] = "amber producer A owns this copy";
#define COPY_SECONDARY "A: independent data 1847"
#elif COPY_VARIANT == 2
OBF_STRING_COPY_SOURCE_V1(exchange_copy_v1, 1)
static const char copy_primary[] = "violet producer B has another payload";
#define COPY_SECONDARY "B: distinct data 9263"
#else
#error COPY_VARIANT must be 1 or 2
#endif

// ID 2 deliberately has C++ local-static storage, without a borrowed-pointer
// reader or an application copy in a constructor or loader callback. The used
// annotation retains the source even though this private keeper is never called.
__attribute__((used, noinline)) static void retain_local_source() {
  OBF_STRING_COPY_SOURCE_V1(exchange_copy_v1, 2)
  static const char copy_secondary[] = COPY_SECONDARY;
}

OBF_STRING_COPY_SOURCE_V1(exchange_copy_v1, 3)
static const char copy_empty[] = "";

OBF_STRING_COPY_DECLARE_V1(exchange_copy_v1);
