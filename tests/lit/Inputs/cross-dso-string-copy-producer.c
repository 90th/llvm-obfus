#include <obf/string_copy.h>

#if COPY_VARIANT == 1
OBF_STRING_COPY_SOURCE_V1(exchange_copy_v1, 1)
static const char copy_primary[] = "amber producer A owns this copy";
OBF_STRING_COPY_SOURCE_V1(exchange_copy_v1, 2)
static const char copy_secondary[] = "A: independent data 1847";
#elif COPY_VARIANT == 2
OBF_STRING_COPY_SOURCE_V1(exchange_copy_v1, 1)
static const char copy_primary[] = "violet producer B has another payload";
OBF_STRING_COPY_SOURCE_V1(exchange_copy_v1, 2)
static const char copy_secondary[] = "B: distinct data 9263";
#else
#error COPY_VARIANT must be 1 or 2
#endif
OBF_STRING_COPY_SOURCE_V1(exchange_copy_v1, 3)
static const char copy_empty[] = "";

OBF_STRING_COPY_DECLARE_V1(exchange_copy_v1);
