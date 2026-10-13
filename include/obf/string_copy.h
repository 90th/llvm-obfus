#pragma once

#include <stddef.h>
#include <stdint.h>

/* Use this declaration macro. The compiler generates the accessor body. */
#ifdef __cplusplus
#define OBF_STRING_COPY_DECLARE_V1(accessor) \
  extern "C" __attribute__((visibility("default"))) \
  int accessor(uint32_t id, char* destination, size_t capacity, size_t* required)
#else
#define OBF_STRING_COPY_DECLARE_V1(accessor) \
  __attribute__((visibility("default"))) \
  int accessor(uint32_t id, char* destination, size_t capacity, size_t* required)
#endif

#define OBF_STRING_COPY_SOURCE_V1(accessor, id) \
  __attribute__((used, annotate("obf.string_copy.v1:" #accessor ":" #id)))

enum obf_string_copy_status {
  OBF_STRING_COPY_OK = 0,
  OBF_STRING_COPY_NEED_CAPACITY = 1,
  OBF_STRING_COPY_UNKNOWN_ID = 2,
  OBF_STRING_COPY_INVALID_ARGUMENT = 3
};

/* required must point to valid size_t storage outside the destination range. */
/* The required size includes NUL. A successful call copies that many bytes. */
/* A null required returns INVALID_ARGUMENT without a write. */
/* A query uses a null destination and zero capacity. It returns NEED_CAPACITY. */
/* Query and error results do not authenticate the payload. */
