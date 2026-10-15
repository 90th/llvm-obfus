#define _GNU_SOURCE
#include "cross-dso-string-copy-api.h"

#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <link.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *const expected[2][3] = {
    {"amber producer A owns this copy", "A: independent data 1847", ""},
    {"violet producer B has another payload", "B: distinct data 9263", ""}};
static unsigned checks, statuses[4], reads;

static void require(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "copy exchange failure: %s\n", message);
    exit(1);
  }
  ++checks;
}

static unsigned mappings(const char *path) {
  FILE *stream = fopen("/proc/self/maps", "r");
  require(stream != NULL, "cannot read process mappings");
  unsigned count = 0;
  char *line = NULL;
  size_t capacity = 0;
  while (getline(&line, &capacity, stream) >= 0) {
    unsigned long start, end, offset, inode;
    unsigned major, minor;
    char permissions[5];
    int position = 0;
    if (sscanf(line, "%lx-%lx %4s %lx %x:%x %lu %n", &start, &end,
               permissions, &offset, &major, &minor, &inode, &position) != 7)
      continue;
    char *name = line + position;
    name[strcspn(name, "\n")] = 0;
    if (strcmp(name, path) == 0)
      ++count;
  }
  free(line);
  require(fclose(stream) == 0, "cannot close process mappings");
  return count;
}

struct image {
  void *handle;
  uintptr_t base;
  char path[PATH_MAX];
};

static struct image load_image(const char *path) {
  struct image result = {0};
  require(realpath(path, result.path) != NULL, "cannot resolve image path");
  result.handle = dlopen(result.path, RTLD_NOW | RTLD_LOCAL);
  if (result.handle == NULL)
    fprintf(stderr, "dlopen: %s\n", dlerror());
  require(result.handle != NULL, "cannot load image");
  struct link_map *map = NULL;
  require(dlinfo(result.handle, RTLD_DI_LINKMAP, &map) == 0 && map != NULL,
          "cannot inspect handle owner");
  result.base = (uintptr_t)map->l_addr;
  require(mappings(result.path) > 0, "loaded image has no mappings");
  return result;
}

static int symbol_is_owned_by(const struct image *image, void *symbol) {
  Dl_info info;
  char resolved[PATH_MAX];
  return dladdr(symbol, &info) != 0 &&
         (uintptr_t)info.dli_fbase == image->base &&
         realpath(info.dli_fname, resolved) != NULL &&
         strcmp(resolved, image->path) == 0;
}

static int checked_copy(const struct image *owner, copy_accessor accessor,
                        uint32_t id, char *destination, size_t capacity,
                        size_t *required) {
  if (!symbol_is_owned_by(owner, (void *)accessor))
    return -1;
  return accessor(id, destination, capacity, required);
}

static void *owned_symbol(struct image *image, const char *name) {
  dlerror();
  void *symbol = dlsym(image->handle, name);
  const char *error = dlerror();
  require(error == NULL && symbol != NULL, "missing handle-scoped symbol");
  require(symbol_is_owned_by(image, symbol),
          "symbol resolved to the wrong producer or consumer");
  return symbol;
}

static void unload_image(struct image *image) {
  void *handle = image->handle;
  image->handle = NULL;
  require(dlclose(handle) == 0, "dlclose failed");
  require(mappings(image->path) == 0, "producer mapping survived dlclose");
  image->base = 0;
}

static void status_is(int actual, int status) {
  require(actual == status, "wrong accessor status");
  ++statuses[status];
}

static void unchanged(const unsigned char *bytes, size_t count) {
  for (size_t index = 0; index < count; ++index)
    require(bytes[index] == 0xa6, "accessor changed a destination sentinel");
}

static uint64_t consume(byte_reader reader, const unsigned char *bytes,
                        size_t count, uint64_t salt) {
  uint64_t weighted = 0;
  for (size_t index = 0; index < count; ++index)
    weighted += (uint64_t)bytes[index] * (index + 1);
  uint64_t oracle = (UINT64_C(0x13579bdf) ^ salt) + weighted +
                    salt * (uint64_t)count * ((uint64_t)count + 1) / 2;
  uint64_t effect = UINT64_C(0xdecafbad);
  uint64_t actual = reader(bytes, count, salt, &effect);
  require(actual == oracle, "consumer returned incorrect byte arithmetic");
  require(effect == (oracle ^ (salt << 1)), "consumer wrote incorrect effect");
  ++reads;
  return actual;
}

static void rejected_calls(copy_accessor accessor, unsigned variant, unsigned id,
                           unsigned char *buffer, size_t *required) {
  size_t length = strlen(expected[variant][id - 1]) + 1;
  *required = SIZE_MAX;
  status_is(accessor(id, NULL, 0, required), COPY_NEED_CAPACITY);
  require(*required == length, "query reported the wrong required size");
  status_is(accessor(id, (char *)buffer, length - 1, required), COPY_NEED_CAPACITY);
  require(*required == length, "short copy reported the wrong required size");
  unchanged(buffer, COPY_BUFFER_SIZE);
  status_is(accessor(UINT32_MAX, (char *)buffer, COPY_BUFFER_SIZE, required),
            COPY_UNKNOWN_ID);
  require(*required == 0, "unknown ID did not clear required size");
  unchanged(buffer, COPY_BUFFER_SIZE);
  status_is(accessor(id, NULL, length, required), COPY_INVALID_ARGUMENT);
  require(*required == length, "invalid destination lost the known size");
  status_is(accessor(id, (char *)buffer, COPY_BUFFER_SIZE, NULL),
            COPY_INVALID_ARGUMENT);
  unchanged(buffer, COPY_BUFFER_SIZE);
}

static void semantic_case(copy_accessor accessor, unsigned variant, unsigned id,
                          unsigned char *copy, byte_reader reader) {
  const char *text = expected[variant][id - 1];
  size_t length = strlen(text) + 1;
  unsigned char buffer[COPY_BUFFER_SIZE];
  size_t required = SIZE_MAX;
  memset(buffer, 0xa6, sizeof(buffer));
  status_is(accessor(id, NULL, 0, &required), COPY_NEED_CAPACITY);
  require(required == length, "required size must include exactly one NUL");
  status_is(accessor(id, (char *)buffer + 7, 0, &required), COPY_NEED_CAPACITY);
  unchanged(buffer, sizeof(buffer));
  status_is(accessor(id, (char *)buffer + 7, length - 1, &required),
            COPY_NEED_CAPACITY);
  require(required == length, "short capacity changed required size");
  unchanged(buffer, sizeof(buffer));
  status_is(accessor(id, NULL, 1, &required), COPY_INVALID_ARGUMENT);
  require(required == length, "null destination changed required size");
  status_is(accessor(id, (char *)buffer + 7, length, NULL), COPY_INVALID_ARGUMENT);
  unchanged(buffer, sizeof(buffer));
  status_is(accessor(id, (char *)buffer + 7, length, &required), COPY_OK);
  require(required == length && memcmp(buffer + 7, text, length) == 0,
          "exact capacity did not copy the exact string and NUL");
  unchanged(buffer, 7);
  unchanged(buffer + 7 + length, sizeof(buffer) - 7 - length);
  memcpy(copy, buffer + 7, length);
  consume(reader, copy, length, 17 + variant * 29 + id);
  memset(buffer, 0xa6, sizeof(buffer));
  status_is(accessor(id, (char *)buffer + 7, sizeof(buffer) - 14, &required), COPY_OK);
  require(required == length && memcmp(buffer + 7, text, length) == 0,
          "large capacity changed the copied string");
  unchanged(buffer, 7);
  unchanged(buffer + 7 + length, sizeof(buffer) - 7 - length);
}

static void semantics(const char *first, const char *second, const char *consumer,
                      const char *incompatible) {
  struct image readers = load_image(consumer);
  byte_reader reader = (byte_reader)owned_symbol(&readers, "exchange_read_bytes");
  struct image producers[2] = {load_image(first), load_image(second)};
  copy_accessor accessors[2];
  for (unsigned variant = 0; variant < 2; ++variant)
    accessors[variant] = (copy_accessor)owned_symbol(&producers[variant],
                                                  "exchange_copy_v1");
  require(producers[0].base != producers[1].base &&
              (void *)accessors[0] != (void *)accessors[1],
          "independent producer handles share an implementation");
  unsigned char copies[2][3][COPY_BUFFER_SIZE] = {{{0}}};
  for (unsigned id = 1; id <= 3; ++id)
    for (unsigned variant = 0; variant < 2; ++variant)
      semantic_case(accessors[variant], variant, id, copies[variant][id - 1], reader);
  unsigned char sentinel[COPY_BUFFER_SIZE];
  memset(sentinel, 0xa6, sizeof(sentinel));
  size_t mismatched_required = SIZE_MAX;
  require(checked_copy(&producers[0], accessors[1], 1, (char *)sentinel,
                       sizeof(sentinel), &mismatched_required) == -1,
          "mismatched accessor and retained owner did not reject the transfer");
  require(mismatched_required == SIZE_MAX, "mismatched owner wrote the required size");
  unchanged(sentinel, sizeof(sentinel));
  for (unsigned variant = 0; variant < 2; ++variant) {
    size_t required;
    rejected_calls(accessors[variant], variant, 1, sentinel, &required);
    status_is(accessors[variant](0, NULL, 0, &required), COPY_UNKNOWN_ID);
    require(required == 0, "unknown query did not clear required size");
    status_is(accessors[variant](0, (char *)sentinel, sizeof(sentinel), NULL),
              COPY_INVALID_ARGUMENT);
    unchanged(sentinel, sizeof(sentinel));
  }
  struct image v2 = load_image(incompatible);
  owned_symbol(&v2, "exchange_copy_v2");
  dlerror();
  require(dlsym(v2.handle, "exchange_copy_v1") == NULL && dlerror() != NULL,
          "v2-only producer unexpectedly provides v1");
  unload_image(&v2);
  uint64_t digest = consume(reader, NULL, 0, 101);
  for (unsigned variant = 0; variant < 2; ++variant) {
    accessors[variant] = NULL;
    unload_image(&producers[variant]);
    require(accessors[variant] == NULL, "producer callable survived unload");
    if (variant == 0) {
      require(mappings(producers[1].path) > 0, "unload removed the other producer");
      unsigned char probe[COPY_BUFFER_SIZE];
      size_t required;
      status_is(accessors[1](1, (char *)probe, sizeof(probe), &required), COPY_OK);
      require(required == strlen(expected[1][0]) + 1 &&
                  memcmp(probe, expected[1][0], required) == 0,
              "live producer changed after the other producer unloaded");
    }
    for (unsigned owner = 0; owner <= variant; ++owner)
      for (unsigned id = 1; id <= 3; ++id) {
        size_t length = strlen(expected[owner][id - 1]) + 1;
        require(memcmp(copies[owner][id - 1], expected[owner][id - 1], length) == 0,
                "caller-owned copy changed after actual producer unload");
        digest += consume(reader, copies[owner][id - 1], length,
                          71 + owner * 43 + id);
      }
  }
  reader = NULL;
  unload_image(&readers);
  printf("{\"ok\":true,\"kind\":\"semantics\",\"checks\":%u,"
         "\"statuses\":[%u,%u,%u,%u],\"reads\":%u,\"digest\":%llu,"
         "\"unmapped\":[true,true],\"missing_v1\":true,\"mismatched_owner_rejected\":true,"
         "\"required_sizes\":[[%zu,%zu,1],[%zu,%zu,1]]}\n",
         checks, statuses[0], statuses[1], statuses[2], statuses[3], reads,
         (unsigned long long)digest, strlen(expected[0][0]) + 1,
         strlen(expected[0][1]) + 1, strlen(expected[1][0]) + 1,
         strlen(expected[1][1]) + 1);
}

struct shared_observation {
  unsigned char destination[COPY_BUFFER_SIZE];
  uint64_t effect;
  size_t required;
  unsigned stage;
  unsigned errors;
};

struct mutation_segment {
  uintptr_t base;
  uintptr_t offset;
  int found;
};

static int find_mutation_segment(struct dl_phdr_info *info, size_t size, void *opaque) {
  (void)size;
  struct mutation_segment *target = opaque;
  if ((uintptr_t)info->dlpi_addr != target->base)
    return 0;
  for (ElfW(Half) index = 0; index < info->dlpi_phnum; ++index) {
    const ElfW(Phdr) *segment = &info->dlpi_phdr[index];
    if (segment->p_type == PT_LOAD && (segment->p_flags & PF_R) &&
        !(segment->p_flags & PF_X) && target->offset >= segment->p_vaddr &&
        target->offset - segment->p_vaddr < segment->p_memsz) {
      target->found = 1;
      return 1;
    }
  }
  return 1;
}

static void mutate_data(struct image *image, uintptr_t offset, unsigned original) {
  uintptr_t address = image->base + offset;
  require(address >= image->base, "mutation address overflow");
  // A producer's BSS tail can occupy an anonymous loader mapping.
  struct mutation_segment target_segment = {image->base, offset, 0};
  dl_iterate_phdr(find_mutation_segment, &target_segment);
  require(target_segment.found, "mutation target is outside producer data segments");
  FILE *stream = fopen("/proc/self/maps", "r");
  require(stream != NULL, "cannot inspect mutation mapping");
  char *line = NULL;
  size_t capacity = 0;
  int protection = -1;
  while (getline(&line, &capacity, stream) >= 0) {
    unsigned long start, end;
    char permissions[5];
    if (sscanf(line, "%lx-%lx %4s", &start, &end, permissions) != 3 ||
        address < start || address >= end)
      continue;
    require(permissions[0] == 'r' && permissions[2] != 'x',
            "mutation target is not producer data");
    protection = PROT_READ | (permissions[1] == 'w' ? PROT_WRITE : 0);
    break;
  }
  free(line);
  require(fclose(stream) == 0 && protection >= 0, "mutation mapping not found");
  long page_size = sysconf(_SC_PAGESIZE);
  require(page_size > 0, "invalid system page size");
  uintptr_t page = address - address % (uintptr_t)page_size;
  if (!(protection & PROT_WRITE))
    require(mprotect((void *)page, (size_t)page_size, protection | PROT_WRITE) == 0,
            "cannot make producer data writable");
  volatile unsigned char *target = (volatile unsigned char *)address;
  require(*target == original, "mutation target does not match ELF data or decoded cache");
  *target ^= 1;
  require(*target == (original ^ 1), "data corruption did not take effect");
  if (!(protection & PROT_WRITE))
    require(mprotect((void *)page, (size_t)page_size, protection) == 0,
            "cannot restore producer data protection");
}

static void tamper(const char *producer, const char *consumer, unsigned variant,
                   unsigned id, const char *mode, int warm, uintptr_t offset,
                   unsigned original, const char *strategy, uintptr_t cache_offset,
                   uintptr_t state_offset, uint64_t cold_status) {
  require(variant < 2 && id >= 1 && id <= 3 && original <= 255, "invalid tamper arguments");
  struct shared_observation *shared = mmap(NULL, sizeof(*shared),
      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  require(shared != MAP_FAILED, "cannot allocate shared observation");
  memset(shared, 0, sizeof(*shared));
  memset(shared->destination, 0xa6, sizeof(shared->destination));
  shared->effect = UINT64_C(0xdecafbad);
  shared->required = SIZE_MAX;
  fflush(NULL);
  pid_t child = fork();
  require(child >= 0, "fork failed");
  if (child == 0) {
    struct image readers = load_image(consumer);
    byte_reader reader = (byte_reader)owned_symbol(&readers, "exchange_read_bytes");
    struct image source = load_image(producer);
    copy_accessor accessor = (copy_accessor)owned_symbol(&source, "exchange_copy_v1");
    size_t length = strlen(expected[variant][id - 1]) + 1;
    const unsigned char *cache = (const unsigned char *)(source.base + cache_offset);
    const volatile uint64_t *state = (const volatile uint64_t *)(source.base + state_offset);
    int lazy = strcmp(strategy, "lazy") == 0;
    if (strcmp(strategy, "ctor") == 0)
      require(memcmp(cache, expected[variant][id - 1], length) == 0,
              "constructor did not authenticate and decode before the first copy");
    else {
      require(strcmp(strategy, "lazy") == 0, "invalid decoder strategy");
      require(state[1] == cold_status && state[2] == cold_status,
              "lazy source state completed before the first copy");
      for (size_t index = 0; index < length; ++index)
        require(cache[index] == 0, "lazy source decoded before the first copy");
    }
    if (warm) {
      unsigned char first[COPY_BUFFER_SIZE];
      size_t required;
      status_is(accessor(id, (char *)first, sizeof(first), &required), COPY_OK);
      require(required == length && memcmp(first, expected[variant][id - 1], length) == 0,
              "first copy was not valid before data corruption");
      consume(reader, first, length, 89 + variant);
    }
    shared->stage = 1;
    mutate_data(&source, offset, original);
    shared->stage = 2;
    rejected_calls(accessor, variant, id, shared->destination, &shared->required);
    shared->errors = 5;
    if (lazy && !warm)
      require(state[1] == cold_status && state[2] == cold_status,
              "ordinary rejection changed the cold authentication state");
    shared->stage = 3;
    int status = accessor(id, (char *)shared->destination + 7, length,
                          &shared->required);
    shared->stage = 4;
    if (status == COPY_OK)
      shared->effect = reader(shared->destination + 7, length, 97,
                              &shared->effect);
    _exit(90);
  }
  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  require(waited == child, "cannot reap tamper child");
  int signal = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
  require(signal == SIGILL,
          "authenticated copy did not terminate with the runtime trap signal");
  require(shared->stage == 3 && shared->errors == 5,
          "query or rejection authenticated corrupted data, or copy returned");
  unchanged(shared->destination, sizeof(shared->destination));
  require(shared->effect == UINT64_C(0xdecafbad),
          "consumer effect changed after rejected authentication");
  require(shared->required == strlen(expected[variant][id - 1]) + 1,
          "copy did not report the known required size before authentication");
  printf("{\"ok\":true,\"kind\":\"tamper\",\"mode\":\"%s\","
         "\"warm\":%s,\"variant\":%u,\"id\":%u,\"signal\":%d,\"stage\":%u,"
         "\"ordinary_rejections\":%u,\"destination_unchanged\":true,"
         "\"effect_unchanged\":true,\"required\":%zu,\"lazy_state_checked\":%s}\n",
         mode, warm ? "true" : "false", variant + 1, id, signal, shared->stage,
         shared->errors, shared->required, strcmp(strategy, "lazy") == 0 ? "true" : "false");
  require(munmap(shared, sizeof(*shared)) == 0, "cannot release shared observation");
}

static unsigned long long number(const char *text) {
  char *end = NULL;
  errno = 0;
  unsigned long long value = strtoull(text, &end, 0);
  require(errno == 0 && end != text && *end == 0, "invalid numeric argument");
  return value;
}

int main(int argc, char **argv) {
  struct rlimit no_core = {0, 0};
  require(setrlimit(RLIMIT_CORE, &no_core) == 0, "cannot disable core dumps");
  alarm(25);
  if (argc == 6 && strcmp(argv[1], "semantics") == 0)
    semantics(argv[2], argv[3], argv[4], argv[5]);
  else if (argc == 14 && strcmp(argv[1], "tamper") == 0)
    tamper(argv[2], argv[3], (unsigned)number(argv[4]) - 1,
           (unsigned)number(argv[5]), argv[6], (int)number(argv[7]),
           (uintptr_t)number(argv[8]), (unsigned)number(argv[9]), argv[10],
           (uintptr_t)number(argv[11]), (uintptr_t)number(argv[12]), (uint64_t)number(argv[13]));
  else {
    fprintf(stderr, "usage: host semantics A.so B.so consumer.so v2.so\n"
                    "       host tamper producer.so consumer.so variant id mode warm rva byte strategy cache_rva state_rva cold_status\n");
    return 2;
  }
  return 0;
}
