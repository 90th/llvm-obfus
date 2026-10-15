#define _GNU_SOURCE
#include "cross-dso-string-copy-api.h"

#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <link.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *const expected[2][3] = {
    {"amber producer A owns this copy", "A: independent data 1847", ""},
    {"violet producer B has another payload", "B: distinct data 9263", ""}};
static _Thread_local unsigned checks, statuses[4], reads;

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

enum { CONCURRENT_WORKERS = 36, WARM_ROUNDS = 4 };

struct source_state {
  uintptr_t cache, state;
  uint64_t cold_status;
};

struct admission {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  pthread_barrier_t start;
  unsigned admitted, completed, outstanding, rejected, parked;
  int accepting, release;
};

struct concurrent_worker {
  struct admission *gate;
  struct image *owner;
  copy_accessor accessor;
  byte_reader reader;
  unsigned variant, id, operation;
  unsigned char saved[COPY_BUFFER_SIZE];
  unsigned checks, statuses[4], reads;
};

static _Thread_local struct concurrent_worker *current_worker;

static struct timespec phase_deadline(void) {
  struct timespec deadline;
  require(clock_gettime(CLOCK_REALTIME, &deadline) == 0, "cannot time host phase");
  deadline.tv_sec += 10;
  return deadline;
}

static void lock_admission(struct admission *gate) {
  require(pthread_mutex_lock(&gate->mutex) == 0, "cannot lock host admission");
}

static void unlock_admission(struct admission *gate) {
  require(pthread_mutex_unlock(&gate->mutex) == 0, "cannot unlock host admission");
}

static int admit_call(struct admission *gate) {
  lock_admission(gate);
  int admitted = gate->accepting;
  if (admitted) {
    ++gate->admitted;
    ++gate->outstanding;
  } else
    ++gate->rejected;
  unlock_admission(gate);
  return admitted;
}

static void complete_call(struct admission *gate) {
  lock_admission(gate);
  require(gate->outstanding > 0, "completed call was not admitted");
  --gate->outstanding;
  ++gate->completed;
  unlock_admission(gate);
}

static int concurrent_copy(uint32_t id, char *destination, size_t capacity,
                           size_t *required) {
  struct concurrent_worker *worker = current_worker;
  require(worker != NULL, "copy has no host worker");
  if (!admit_call(worker->gate))
    return -1;
  int result = checked_copy(worker->owner, worker->accessor, id, destination,
                            capacity, required);
  require(result >= 0, "concurrent accessor has the wrong owner");
  complete_call(worker->gate);
  return result;
}

static void copied_bytes(struct concurrent_worker *worker,
                         const unsigned char *buffer, size_t required) {
  size_t length = strlen(expected[worker->variant][worker->id - 1]) + 1;
  require(required == length &&
              memcmp(buffer + 7, expected[worker->variant][worker->id - 1], length) == 0,
          "concurrent copy changed bytes, NUL, or required size");
  unchanged(buffer, 7);
  unchanged(buffer + 7 + length, COPY_BUFFER_SIZE - 7 - length);
  memcpy(worker->saved, buffer + 7, length);
}

static void cold_application_call(struct concurrent_worker *worker) {
  unsigned char buffer[COPY_BUFFER_SIZE];
  memset(buffer, 0xa6, sizeof(buffer));
  size_t required = SIZE_MAX;
  size_t length = strlen(expected[worker->variant][worker->id - 1]) + 1;
  switch (worker->operation) {
  case 0:
    status_is(concurrent_copy(worker->id, (char *)buffer + 7, length, &required), COPY_OK);
    copied_bytes(worker, buffer, required);
    consume(worker->reader, worker->saved, length, 131 + worker->variant + worker->id);
    return;
  case 1:
    status_is(concurrent_copy(worker->id, NULL, 0, &required), COPY_NEED_CAPACITY);
    break;
  case 2:
    status_is(concurrent_copy(worker->id, (char *)buffer + 7, length - 1, &required),
              COPY_NEED_CAPACITY);
    break;
  case 3:
    status_is(concurrent_copy(UINT32_MAX, (char *)buffer + 7, length, &required),
              COPY_UNKNOWN_ID);
    require(required == 0, "concurrent unknown ID did not clear required size");
    unchanged(buffer, sizeof(buffer));
    return;
  case 4:
    status_is(concurrent_copy(worker->id, NULL, length, &required), COPY_INVALID_ARGUMENT);
    break;
  default:
    status_is(concurrent_copy(worker->id, (char *)buffer + 7, length, NULL),
              COPY_INVALID_ARGUMENT);
    require(required == SIZE_MAX, "null-required call changed worker required storage");
    unchanged(buffer, sizeof(buffer));
    return;
  }
  require(required == length, "concurrent rejection lost the exact required size");
  unchanged(buffer, sizeof(buffer));
}

static void *concurrent_worker_main(void *opaque) {
  struct concurrent_worker *worker = opaque;
  struct admission *gate = worker->gate;
  current_worker = worker;
  int barrier = pthread_barrier_wait(&gate->start);
  require(barrier == 0 || barrier == PTHREAD_BARRIER_SERIAL_THREAD,
          "cannot release application start barrier");
  cold_application_call(worker);
  for (unsigned round = 0; round < WARM_ROUNDS; ++round)
    semantic_case(concurrent_copy, worker->variant, worker->id, worker->saved,
                  worker->reader);

  require(admit_call(gate), "shutdown work was rejected before admission close");
  lock_admission(gate);
  ++gate->parked;
  require(pthread_cond_broadcast(&gate->condition) == 0, "cannot announce parked work");
  struct timespec deadline = phase_deadline();
  while (!gate->release)
    require(pthread_cond_timedwait(&gate->condition, &gate->mutex, &deadline) == 0,
            "host did not release admitted shutdown work in time");
  unlock_admission(gate);
  // This ticket is outstanding in the host, not executing producer code.
  unsigned char final[COPY_BUFFER_SIZE];
  memset(final, 0xa6, sizeof(final));
  size_t required = SIZE_MAX;
  size_t length = strlen(expected[worker->variant][worker->id - 1]) + 1;
  status_is(checked_copy(worker->owner, worker->accessor, worker->id,
                         (char *)final + 7, length, &required), COPY_OK);
  complete_call(gate);
  copied_bytes(worker, final, required);
  consume(worker->reader, worker->saved, length, 173 + worker->variant + worker->id);
  worker->accessor = NULL;
  worker->reader = NULL;
  current_worker = NULL;
  worker->checks = checks;
  worker->reads = reads;
  memcpy(worker->statuses, statuses, sizeof(statuses));
  return NULL;
}

static void inspect_sources(struct image producers[2],
                            const struct source_state sources[2][3],
                            const char *strategy, unsigned used, int before) {
  if (strcmp(strategy, "raw") == 0)
    return;
  int lazy = strcmp(strategy, "lazy") == 0;
  for (unsigned variant = 0; variant < 2; ++variant)
    for (unsigned source = 0; source < 3; ++source) {
      const struct source_state *metadata = &sources[variant][source];
      require(metadata->cache != 0 && metadata->state != 0 &&
                  metadata->cache <= UINTPTR_MAX - producers[variant].base &&
                  metadata->state <= UINTPTR_MAX - producers[variant].base,
              "invalid private source offsets");
      const unsigned char *cache =
          (const unsigned char *)(producers[variant].base + metadata->cache);
      const volatile uint64_t *state =
          (const volatile uint64_t *)(producers[variant].base + metadata->state);
      size_t length = strlen(expected[variant][source]) + 1;
      int cold = lazy && (before || !(used & (1u << (variant * 3 + source))));
      if (cold) {
        require(state[1] == metadata->cold_status && state[2] == metadata->cold_status,
                "lazy source completed before its first application copy");
        for (size_t index = 0; index < length; ++index)
          require(cache[index] == 0, "lazy source cache was not truly cold");
      } else {
        require(memcmp(cache, expected[variant][source], length) == 0,
                "decoded source cache differs after constructor or joined copies");
        if (lazy)
          require(state[1] != metadata->cold_status && state[2] != 0,
                  "joined copies did not complete authenticated lazy decoding");
      }
    }
}

static void concurrency(const char *first, const char *second, const char *consumer,
                        const char *strategy, const char *scenario,
                        const struct source_state sources[2][3]) {
  require(strcmp(strategy, "raw") == 0 || strcmp(strategy, "lazy") == 0 ||
              strcmp(strategy, "ctor") == 0, "invalid concurrency strategy");
  unsigned same_id = 0;
  if (strcmp(scenario, "same-1") == 0)
    same_id = 1;
  else if (strcmp(scenario, "same-2") == 0)
    same_id = 2;
  else if (strcmp(scenario, "same-3") == 0)
    same_id = 3;
  else
    require(strcmp(scenario, "independent-sources") == 0 ||
                strcmp(scenario, "independent-producers") == 0,
            "invalid concurrency scenario");
  struct image readers = load_image(consumer);
  byte_reader reader = (byte_reader)owned_symbol(&readers, "exchange_read_bytes");
  struct image producers[2] = {load_image(first), load_image(second)};
  copy_accessor accessors[2];
  for (unsigned variant = 0; variant < 2; ++variant)
    accessors[variant] = (copy_accessor)owned_symbol(&producers[variant],
                                                  "exchange_copy_v1");
  require(producers[0].base != producers[1].base &&
              (void *)accessors[0] != (void *)accessors[1],
          "concurrent producers are not independent instances");
  struct admission gate = {0};
  gate.accepting = 1;
  require(pthread_mutex_init(&gate.mutex, NULL) == 0 &&
              pthread_cond_init(&gate.condition, NULL) == 0 &&
              pthread_barrier_init(&gate.start, NULL, CONCURRENT_WORKERS + 1) == 0,
          "cannot initialize host concurrency phases");
  struct concurrent_worker workers[CONCURRENT_WORKERS] = {{0}};
  pthread_t threads[CONCURRENT_WORKERS];
  unsigned used = 0;
  for (unsigned index = 0; index < CONCURRENT_WORKERS; ++index) {
    unsigned group = index / 6;
    struct concurrent_worker *worker = &workers[index];
    worker->variant = same_id ? group % 2 :
        (strcmp(scenario, "independent-producers") == 0 ? group / 3 : 0);
    worker->id = same_id ? same_id : group % 3 + 1;
    worker->operation = index % 6;
    worker->gate = &gate;
    worker->owner = &producers[worker->variant];
    worker->accessor = accessors[worker->variant];
    worker->reader = reader;
    used |= 1u << (worker->variant * 3 + worker->id - 1);
    require(pthread_create(&threads[index], NULL, concurrent_worker_main, worker) == 0,
            "cannot start application worker");
  }
  // Workers cannot call either module until this host enters the barrier.
  inspect_sources(producers, sources, strategy, used, 1);
  int barrier = pthread_barrier_wait(&gate.start);
  require(barrier == 0 || barrier == PTHREAD_BARRIER_SERIAL_THREAD,
          "cannot start simultaneous application calls");
  lock_admission(&gate);
  struct timespec deadline = phase_deadline();
  while (gate.parked != CONCURRENT_WORKERS)
    require(pthread_cond_timedwait(&gate.condition, &gate.mutex, &deadline) == 0,
            "application workers did not reach host shutdown phase in time");
  gate.accepting = 0;
  unsigned outstanding_at_close = gate.outstanding;
  require(outstanding_at_close == CONCURRENT_WORKERS &&
              gate.admitted == gate.completed + outstanding_at_close,
          "admission did not close with exactly the parked host work outstanding");
  unlock_admission(&gate);
  unsigned char rejected[COPY_BUFFER_SIZE];
  memset(rejected, 0xa6, sizeof(rejected));
  size_t rejected_required = SIZE_MAX;
  current_worker = &workers[0];
  for (unsigned attempt = 0; attempt < 3; ++attempt)
    require(concurrent_copy(1, (char *)rejected, sizeof(rejected), &rejected_required) == -1,
            "post-close admission reached a module");
  current_worker = NULL;
  require(rejected_required == SIZE_MAX, "post-close rejection changed required size");
  unchanged(rejected, sizeof(rejected));
  lock_admission(&gate);
  require(gate.outstanding == outstanding_at_close && gate.rejected == 3,
          "post-close admission changed producer call accounting");
  gate.release = 1;
  require(pthread_cond_broadcast(&gate.condition) == 0, "cannot drain admitted work");
  unlock_admission(&gate);
  unsigned char owner_copies[2][3][COPY_BUFFER_SIZE] = {{{0}}};
  for (unsigned index = 0; index < CONCURRENT_WORKERS; ++index) {
    struct concurrent_worker *worker = &workers[index];
    require(pthread_join(threads[index], NULL) == 0, "cannot join application worker");
    require(worker->accessor == NULL && worker->reader == NULL,
            "worker retained a callable after drain");
    checks += worker->checks;
    reads += worker->reads;
    for (unsigned status = 0; status < 4; ++status)
      statuses[status] += worker->statuses[status];
    memcpy(owner_copies[worker->variant][worker->id - 1], worker->saved,
           strlen(expected[worker->variant][worker->id - 1]) + 1);
    worker->owner = NULL;
  }
  require(gate.outstanding == 0 && gate.admitted == gate.completed &&
              gate.completed == CONCURRENT_WORKERS * (2 + 7 * WARM_ROUNDS),
          "drained producer call accounting differs from completed work");
  inspect_sources(producers, sources, strategy, used, 0);
  for (unsigned variant = 0; variant < 2; ++variant) {
    accessors[variant] = NULL;
    require(accessors[variant] == NULL, "owner retained a producer callable");
  }
  for (unsigned variant = 0; variant < 2; ++variant)
    unload_image(&producers[variant]);
  uint64_t digest = 0;
  for (unsigned index = 0; index < CONCURRENT_WORKERS; ++index) {
    struct concurrent_worker *worker = &workers[index];
    size_t length = strlen(expected[worker->variant][worker->id - 1]) + 1;
    require(memcmp(worker->saved, expected[worker->variant][worker->id - 1], length) == 0,
            "saved worker bytes changed after producer mapping removal");
    digest += consume(reader, worker->saved, length, 211 + index);
  }
  unsigned owner_reads = 0;
  for (unsigned variant = 0; variant < 2; ++variant)
    for (unsigned source = 0; source < 3; ++source)
      if (used & (1u << (variant * 3 + source))) {
        size_t length = strlen(expected[variant][source]) + 1;
        require(memcmp(owner_copies[variant][source], expected[variant][source], length) == 0,
                "saved owner bytes changed after producer mapping removal");
        digest += consume(reader, owner_copies[variant][source], length,
                          271 + variant * 3 + source);
        ++owner_reads;
      }
  reader = NULL;
  unload_image(&readers);
  require(pthread_barrier_destroy(&gate.start) == 0 &&
              pthread_cond_destroy(&gate.condition) == 0 &&
              pthread_mutex_destroy(&gate.mutex) == 0,
          "cannot release host concurrency phases");
  printf("{\"ok\":true,\"kind\":\"concurrency\",\"scenario\":\"%s\","
         "\"strategy\":\"%s\",\"workers\":%u,\"warm_rounds\":%u,"
         "\"barrier_started\":true,\"cold_state_checked\":%s,"
         "\"admitted\":%u,\"completed\":%u,\"host_parked_at_close\":%u,"
         "\"post_close_rejected\":%u,\"drained\":true,\"callables_cleared\":true,"
         "\"unmapped\":[true,true],\"copies_after_unload\":%u,\"owner_copies_after_unload\":%u,"
         "\"decoder_overlap_proven\":false,\"checks\":%u,\"statuses\":[%u,%u,%u,%u],"
         "\"reads\":%u,\"digest\":%llu}\n",
         scenario, strategy, CONCURRENT_WORKERS, WARM_ROUNDS,
         strcmp(strategy, "lazy") == 0 ? "true" : "false",
         gate.admitted, gate.completed, outstanding_at_close, gate.rejected,
         CONCURRENT_WORKERS, owner_reads, checks,
         statuses[0], statuses[1], statuses[2], statuses[3], reads,
         (unsigned long long)digest);
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
  else if ((argc == 7 || argc == 25) && strcmp(argv[1], "concurrent") == 0) {
    int raw = strcmp(argv[5], "raw") == 0;
    require(argc == (raw ? 7 : 25), "concurrency metadata does not match strategy");
    struct source_state sources[2][3] = {{{0}}};
    if (!raw)
      for (unsigned variant = 0; variant < 2; ++variant)
        for (unsigned source = 0; source < 3; ++source) {
          unsigned argument = 7 + (variant * 3 + source) * 3;
          sources[variant][source].cache = (uintptr_t)number(argv[argument]);
          sources[variant][source].state = (uintptr_t)number(argv[argument + 1]);
          sources[variant][source].cold_status = (uint64_t)number(argv[argument + 2]);
        }
    concurrency(argv[2], argv[3], argv[4], argv[5], argv[6], sources);
  }
  else {
    fprintf(stderr, "usage: host semantics A.so B.so consumer.so v2.so\n"
                    "       host tamper producer.so consumer.so variant id mode warm rva byte strategy cache_rva state_rva cold_status\n"
                    "       host concurrent A.so B.so consumer.so raw|lazy|ctor scenario [cache_rva state_rva cold_status x6]\n");
    return 2;
  }
  return 0;
}
