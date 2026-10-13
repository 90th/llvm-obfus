#ifndef CROSS_DSO_STRING_COPY_API_H
#define CROSS_DSO_STRING_COPY_API_H

#include <stddef.h>
#include <stdint.h>

typedef int (*copy_accessor)(uint32_t, char *, size_t, size_t *);
typedef uint64_t (*byte_reader)(const unsigned char *, uint64_t, uint64_t,
                               uint64_t *);

enum {
  COPY_OK = 0,
  COPY_NEED_CAPACITY = 1,
  COPY_UNKNOWN_ID = 2,
  COPY_INVALID_ARGUMENT = 3,
  COPY_BUFFER_SIZE = 256
};

#endif
