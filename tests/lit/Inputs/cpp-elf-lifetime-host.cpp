#include "cpp-elf-lifetime-api.h"

#include <cerrno>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <limits>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>

#if !defined(__linux__) || !defined(__GLIBC__)
#error "The lifetime host requires Linux with glibc."
#endif

namespace {
constexpr unsigned trace[] = {1, 2, 3, 5, 2, 4, 6, 7, 7, 8, 9, 10};
constexpr unsigned trace_size = sizeof(trace) / sizeof(trace[0]);
constexpr U failed_touch = std::numeric_limits<U>::max();

struct Step {
  U result;
  U effect;
};

// Numeric bytes and separately written rotation arithmetic are independent of
// both the protected implementation and the raw library's oracle translation unit.
Step oracle(unsigned stage, U generation, U previous) noexcept {
  constexpr unsigned char text[] = {108, 105, 102, 101, 99, 121, 99, 108, 101,
                                   45,  97,  117, 116, 104, 45, 118, 49, 45,
                                   112, 97,  121, 108, 111, 97, 100};
  const U sum = previous + generation * UINT64_C(0x9e3779b97f4a7c15) +
                U(stage) * UINT64_C(0x100000001b3);
  const U rotated = (sum >> (64 - 11)) | (sum << 11);
  const U value = rotated ^ (U(text[stage % 25]) * UINT64_C(0xa0761d6478bd642f));
  const U effect = value + U(stage) * 13;
  return {value ^ effect, effect};
}

Step expected_at(U generation, unsigned index) noexcept {
  Step step{0, 0};
  for (unsigned i = 0; i <= index; ++i)
    step = oracle(trace[i], generation, step.effect);
  return step;
}

bool diagnose(const char *format, ...) noexcept {
  std::fputs("lifetime host: ", stderr);
  va_list args;
  va_start(args, format);
  std::vfprintf(stderr, format, args);
  va_end(args);
  std::fputc('\n', stderr);
  return false;
}

[[noreturn]] void synchronization_fatal(const char *operation, int error) noexcept {
  diagnose("fatal synchronization failure in %s: %s", operation,
           std::strerror(error));
  // A broken mutex/join prevents proving safe worker cleanup. This is a deliberate
  // process-fatal infrastructure failure, not an assertion on library behavior.
  std::_Exit(EXIT_FAILURE);
}

void lock(pthread_mutex_t *mutex) noexcept {
  const int error = pthread_mutex_lock(mutex);
  if (error)
    synchronization_fatal("pthread_mutex_lock", error);
}

void unlock(pthread_mutex_t *mutex) noexcept {
  const int error = pthread_mutex_unlock(mutex);
  if (error)
    synchronization_fatal("pthread_mutex_unlock", error);
}

struct Event {
  unsigned stage;
  U result;
  U effect;
};

struct Generation {
  bool armed;
  unsigned count;
  U expected_effect;
  Event events[trace_size];
};

struct Ledger {
  U requested_generation;
  unsigned count;
  bool failed;
  bool exit_phase;
  bool verify_nodelete_exit;
  Generation generations[3];
};

// These objects have no C++ destructors. NODELETE finalizers can call the host
// after main returns; neither their storage nor this mutex is ever destroyed.
Ledger ledger{};
pthread_mutex_t ledger_mutex = PTHREAD_MUTEX_INITIALIZER;

void observer_failure(const char *format, ...) noexcept {
  if (ledger.failed)
    return;
  ledger.failed = true;
  std::fputs("lifetime host observer: ", stderr);
  va_list args;
  va_start(args, format);
  std::vfprintf(stderr, format, args);
  va_end(args);
  std::fputc('\n', stderr);
}

void request_generation(U generation, bool actual_load) noexcept {
  lock(&ledger_mutex);
  ledger.requested_generation = generation;
  if (actual_load)
    ledger.generations[generation].armed = true;
  unlock(&ledger_mutex);
}

bool expect_events(U generation, unsigned count, const char *point) noexcept {
  lock(&ledger_mutex);
  const bool failed = ledger.failed;
  const unsigned actual = ledger.generations[generation].count;
  unlock(&ledger_mutex);
  if (failed)
    return diagnose("generation %" PRIu64 " failed its observer oracle at %s",
                    generation, point);
  if (actual != count)
    return diagnose("generation %" PRIu64 " at %s: expected %u events, got %u",
                    generation, point, count, actual);
  return true;
}

Generation copy_generation(U generation) noexcept {
  lock(&ledger_mutex);
  const Generation copy = ledger.generations[generation];
  unlock(&ledger_mutex);
  return copy;
}

void nodelete_exit_check() noexcept {
  lock(&ledger_mutex);
  const bool enabled = ledger.verify_nodelete_exit;
  const bool valid = !ledger.failed && ledger.generations[1].count == trace_size &&
                     ledger.generations[2].count == 0 && ledger.count == trace_size;
  unlock(&ledger_mutex);
  if (enabled && !valid) {
    diagnose("NODELETE exit did not complete the exact local/global destructor trace");
    std::_Exit(EXIT_FAILURE);
  }
}

struct Identity {
  unsigned device_major;
  unsigned device_minor;
  unsigned long long inode;
};

bool mapping(const Identity &identity, bool &mapped) noexcept {
  FILE *maps = std::fopen("/proc/self/maps", "r");
  if (!maps)
    return diagnose("opening /proc/self/maps: %s", std::strerror(errno));
  unsigned matching_mappings = 0;
  bool valid = true;
  char line[8192];
  while (std::fgets(line, sizeof(line), maps)) {
    if (!std::strchr(line, '\n') && !std::feof(maps)) {
      diagnose("oversized /proc/self/maps record");
      valid = false;
      break;
    }
    unsigned long long first, last, offset, inode;
    unsigned device_major, device_minor;
    char permissions[5];
    if (std::sscanf(line, "%llx-%llx %4s %llx %x:%x %llu", &first, &last,
                    permissions, &offset, &device_major, &device_minor, &inode) != 7 ||
        first >= last) {
      diagnose("invalid /proc/self/maps record");
      valid = false;
      break;
    }
    if (device_major == identity.device_major &&
        device_minor == identity.device_minor && inode == identity.inode)
      ++matching_mappings;
  }
  if (std::ferror(maps)) {
    diagnose("reading /proc/self/maps: %s", std::strerror(errno ? errno : EIO));
    valid = false;
  }
  if (std::fclose(maps)) {
    diagnose("closing /proc/self/maps: %s", std::strerror(errno));
    valid = false;
  }
  // A read failure is never converted into an observation of unmapping.
  if (valid)
    mapped = matching_mappings != 0;
  return valid;
}

bool expect_mapping(const Identity &identity, bool wanted, bool &observation,
                    U generation, const char *point) noexcept {
  if (!mapping(identity, observation))
    return false;
  if (observation != wanted)
    return diagnose("generation %" PRIu64 " at %s: expected mapping %s, got %s",
                    generation, point, wanted ? "present" : "absent",
                    observation ? "present" : "absent");
  return true;
}

using Touch = U (*)();
using Snapshot = U (*)() noexcept;

class Library {
public:
  Touch touch = nullptr;
  Snapshot snapshot = nullptr;

  ~Library() {
    if (handle_ && !close())
      std::_Exit(EXIT_FAILURE);
  }

  bool open(const char *path, int flags, bool symbols) noexcept {
    handle_ = dlopen(path, flags);
    if (!handle_)
      return diagnose("dlopen: %s", dlerror());
    if (!symbols)
      return true;
    dlerror();
    void *address = dlsym(handle_, "lifetime_touch");
    const char *error = dlerror();
    if (error) {
      address = nullptr;
      return diagnose("dlsym lifetime_touch: %s", error);
    }
    touch = reinterpret_cast<Touch>(address);
    address = nullptr;
    dlerror();
    address = dlsym(handle_, "lifetime_snapshot");
    error = dlerror();
    if (error) {
      address = nullptr;
      clear_symbols();
      return diagnose("dlsym lifetime_snapshot: %s", error);
    }
    snapshot = reinterpret_cast<Snapshot>(address);
    address = nullptr;
    if (!touch || !snapshot) {
      clear_symbols();
      return diagnose("library returned a null callable symbol");
    }
    return true;
  }

  void clear_symbols() noexcept {
    touch = nullptr;
    snapshot = nullptr;
  }

  bool close() noexcept {
    clear_symbols();
    void *closing = handle_;
    handle_ = nullptr;
    const int result = closing ? dlclose(closing) : 0;
    closing = nullptr;
    return result == 0 || diagnose("dlclose: %s", dlerror());
  }

private:
  void *handle_ = nullptr;
};

class Worker {
public:
  U first_return = 0;
  U second_return = 0;
  U snapshot_effect = 0;

  ~Worker() {
    finish();
    int error = pthread_cond_destroy(&condition_);
    if (error)
      synchronization_fatal("pthread_cond_destroy", error);
    error = pthread_mutex_destroy(&mutex_);
    if (error)
      synchronization_fatal("pthread_mutex_destroy", error);
  }

  bool start(Touch touch, Snapshot snapshot, U generation) noexcept {
    touch_ = touch;
    snapshot_ = snapshot;
    touch = nullptr;
    snapshot = nullptr;
    generation_ = generation;
    const int error = pthread_create(&thread_, nullptr, run, this);
    if (error) {
      touch_ = nullptr;
      snapshot_ = nullptr;
      return diagnose("pthread_create: %s", std::strerror(error));
    }
    started_ = true;
    return true;
  }

  bool await_parked() noexcept {
    timespec deadline{};
    if (clock_gettime(CLOCK_REALTIME, &deadline))
      return diagnose("clock_gettime: %s", std::strerror(errno));
    deadline.tv_sec += 30;
    lock(&mutex_);
    while (!parked_) {
      const int error = pthread_cond_timedwait(&condition_, &mutex_, &deadline);
      if (error == ETIMEDOUT) {
        unlock(&mutex_);
        return diagnose("worker did not park within 30 seconds");
      }
      if (error)
        synchronization_fatal("pthread_cond_timedwait", error);
    }
    const bool valid = valid_ && touch_ == nullptr && snapshot_ == nullptr;
    unlock(&mutex_);
    return valid || diagnose("worker return/effect oracle or callable clearing failed");
  }

  void finish() noexcept {
    if (!started_)
      return;
    lock(&mutex_);
    released_ = true;
    const int signal_error = pthread_cond_broadcast(&condition_);
    if (signal_error)
      synchronization_fatal("pthread_cond_broadcast", signal_error);
    unlock(&mutex_);
    const int join_error = pthread_join(thread_, nullptr);
    if (join_error)
      synchronization_fatal("pthread_join", join_error);
    started_ = false;
    touch_ = nullptr;
    snapshot_ = nullptr;
  }

private:
  static void *run(void *argument) noexcept {
    Worker &worker = *static_cast<Worker *>(argument);
    Touch touch = worker.touch_;
    Snapshot snapshot = worker.snapshot_;
    worker.touch_ = nullptr;
    worker.snapshot_ = nullptr;
    bool valid = true;
    try {
      worker.first_return = touch();
      worker.second_return = touch();
      worker.snapshot_effect = snapshot();
      const Step first = expected_at(worker.generation_, 7);
      const Step second = expected_at(worker.generation_, 8);
      if (worker.first_return != first.result)
        valid = diagnose("generation %" PRIu64 " first worker touch: expected %" PRIu64
                         ", got %" PRIu64,
                         worker.generation_, first.result, worker.first_return);
      if (worker.second_return != second.result)
        valid = diagnose("generation %" PRIu64 " second worker touch: expected %" PRIu64
                         ", got %" PRIu64,
                         worker.generation_, second.result, worker.second_return);
      if (worker.snapshot_effect != second.effect)
        valid = diagnose("generation %" PRIu64 " worker snapshot: expected %" PRIu64
                         ", got %" PRIu64,
                         worker.generation_, second.effect, worker.snapshot_effect);
    } catch (...) {
      valid = diagnose("generation %" PRIu64 " unexpected exception escaped worker touch",
                       worker.generation_);
    }
    // Both the shared capture and each thread-local callable are gone before the
    // host can observe parked_. The only later DSO execution is the TLS finalizer.
    touch = nullptr;
    snapshot = nullptr;
    lock(&worker.mutex_);
    worker.valid_ = valid;
    worker.parked_ = true;
    int error = pthread_cond_broadcast(&worker.condition_);
    if (error)
      synchronization_fatal("pthread_cond_broadcast", error);
    while (!worker.released_) {
      error = pthread_cond_wait(&worker.condition_, &worker.mutex_);
      if (error)
        synchronization_fatal("pthread_cond_wait", error);
    }
    unlock(&worker.mutex_);
    return nullptr;
  }

  pthread_mutex_t mutex_ = PTHREAD_MUTEX_INITIALIZER;
  pthread_cond_t condition_ = PTHREAD_COND_INITIALIZER;
  pthread_t thread_{};
  bool started_ = false;
  bool parked_ = false;
  bool released_ = false;
  bool valid_ = false;
  Touch touch_ = nullptr;
  Snapshot snapshot_ = nullptr;
  U generation_ = 0;
};

enum class Mode { Joined, Tls, Nodelete };

struct Outcome {
  U generation;
  U failure_return;
  U touch_returns[2];
  U worker_snapshot;
  bool before_load;
  bool loaded;
  bool after_close;
  bool after_thread_exit;
  bool reopened;
  bool after_reclose;
  bool final;
};

bool run_generation(const char *path, const Identity &identity, Mode mode,
                    U generation, Outcome &outcome) noexcept {
  outcome.generation = generation;
  if (!expect_mapping(identity, false, outcome.before_load, generation, "before load"))
    return false;
  request_generation(generation, true);
  Library library;
  // Declaration order ensures every error path releases and joins the worker
  // before the Library guard clears pointers and closes any still-open handle.
  Worker worker;
  const int flags = RTLD_NOW | RTLD_LOCAL | (mode == Mode::Nodelete ? RTLD_NODELETE : 0);
  if (!library.open(path, flags, true) ||
      !expect_events(generation, 1, "global constructor") ||
      !expect_mapping(identity, true, outcome.loaded, generation, "loaded"))
    return false;

  U failed_effect = 0;
  try {
    outcome.failure_return = library.touch();
    failed_effect = library.snapshot();
  } catch (...) {
    return diagnose("generation %" PRIu64 " unexpected exception escaped failed touch",
                    generation);
  }
  if (outcome.failure_return != failed_touch)
    return diagnose("generation %" PRIu64 " initial touch: expected failure sentinel, got %"
                    PRIu64, generation, outcome.failure_return);
  if (!expect_events(generation, 4, "throw/cleanup/catch"))
    return false;
  const U expected_failed_effect = expected_at(generation, 3).effect;
  if (failed_effect != expected_failed_effect)
    return diagnose("generation %" PRIu64 " failure snapshot: expected %" PRIu64
                    ", got %" PRIu64, generation, expected_failed_effect, failed_effect);

  if (!worker.start(library.touch, library.snapshot, generation))
    return false;
  library.clear_symbols();
  if (!worker.await_parked() || !expect_events(generation, 9, "worker parked"))
    return false;
  outcome.touch_returns[0] = worker.first_return;
  outcome.touch_returns[1] = worker.second_return;
  outcome.worker_snapshot = worker.snapshot_effect;

  if (mode == Mode::Tls) {
    if (!library.close() ||
        !expect_events(generation, 9, "dlclose with live worker TLS") ||
        !expect_mapping(identity, true, outcome.after_close, generation,
                        "dlclose with live worker TLS"))
      return false;
    worker.finish();
    if (!mapping(identity, outcome.after_thread_exit))
      return false;
    if (outcome.after_thread_exit) {
      if (!expect_events(generation, 10, "TLS destructor with retained mapping"))
        return false;
      // This is a loader reference only: no dlsym, no touch, and generation stays
      // unchanged. A new constructor here is rejected by the incremental oracle.
      if (!library.open(path, RTLD_NOW | RTLD_LOCAL, false) ||
          !expect_events(generation, 10, "retained image reopened") ||
          !library.close())
        return false;
    }
    if (!expect_events(generation, trace_size, "final TLS unload") ||
        !expect_mapping(identity, false, outcome.final, generation, "final TLS unload"))
      return false;
  } else {
    worker.finish();
    if (!expect_events(generation, 10, "joined worker TLS destructor"))
      return false;
    if (!library.close())
      return false;
    const bool retained = mode == Mode::Nodelete;
    if (!expect_events(generation, retained ? 10 : trace_size, "joined dlclose") ||
        !expect_mapping(identity, retained, outcome.after_close, generation,
                        "joined dlclose"))
      return false;
    if (retained) {
      // Asking for generation two must not change the live generation-one DSO.
      request_generation(2, false);
      if (!library.open(path, RTLD_NOW | RTLD_LOCAL, false) ||
          !expect_events(generation, 10, "NODELETE reopen without constructors") ||
          !expect_mapping(identity, true, outcome.reopened, generation,
                          "NODELETE reopen") ||
          !library.close() ||
          !expect_events(generation, 10, "NODELETE reclose") ||
          !expect_mapping(identity, true, outcome.after_reclose, generation,
                          "NODELETE reclose"))
        return false;
      outcome.final = outcome.after_reclose;
    } else {
      outcome.final = outcome.after_close;
    }
  }
  return true;
}

const char *boolean(bool value) noexcept { return value ? "true" : "false"; }

void print_counts(const unsigned *counts) noexcept {
  std::putchar('[');
  for (unsigned stage = 1; stage <= 10; ++stage)
    std::printf("%s%u", stage == 1 ? "" : ",", counts[stage]);
  std::putchar(']');
}

bool print_result(const char *mode_name, Mode mode, const Outcome *outcomes,
                  unsigned generations) noexcept {
  unsigned total_counts[11]{};
  unsigned total_events = 0;
  for (unsigned i = 0; i < generations; ++i) {
    const Generation record = copy_generation(outcomes[i].generation);
    total_events += record.count;
    for (unsigned j = 0; j < record.count; ++j)
      ++total_counts[record.events[j].stage];
  }
  std::printf("{\"ok\":true,\"mode\":\"%s\",\"cause\":\"%s\","
              "\"actual_generations\":%u,\"requested_generations\":2,"
              "\"loads\":%u,\"unloads\":%u,\"event_count\":%u,"
              "\"exact_event_checks\":%u,\"return_checks\":%u,\"effect_checks\":%u,"
              "\"stage_counts\":",
              mode_name, mode_name, generations, generations,
              mode == Mode::Nodelete ? 0 : generations, total_events, total_events,
              3 * generations, total_events + 2 * generations);
  print_counts(total_counts);
  std::fputs(",\"generations\":[", stdout);
  for (unsigned i = 0; i < generations; ++i) {
    const Outcome &outcome = outcomes[i];
    const Generation record = copy_generation(outcome.generation);
    unsigned counts[11]{};
    for (unsigned j = 0; j < record.count; ++j)
      ++counts[record.events[j].stage];
    std::printf("%s{\"generation\":%" PRIu64 ",\"event_count\":%u,\"stage_counts\":",
                i ? "," : "", outcome.generation, record.count);
    print_counts(counts);
    std::fputs(",\"stages\":[", stdout);
    for (unsigned j = 0; j < record.count; ++j)
      std::printf("%s%u", j ? "," : "", record.events[j].stage);
    std::printf("],\"failure_return\":%" PRIu64 ",\"touch_returns\":[%" PRIu64
                ",%" PRIu64 "],\"worker_snapshot\":%" PRIu64
                ",\"final_effect\":%" PRIu64 ",\"mappings\":{"
                "\"before_load\":%s,\"loaded\":%s,\"after_close\":%s",
                outcome.failure_return, outcome.touch_returns[0], outcome.touch_returns[1],
                outcome.worker_snapshot, record.events[record.count - 1].effect,
                boolean(outcome.before_load), boolean(outcome.loaded),
                boolean(outcome.after_close));
    if (mode == Mode::Tls)
      std::printf(",\"after_thread_exit\":%s", boolean(outcome.after_thread_exit));
    if (mode == Mode::Nodelete)
      std::printf(",\"reopened\":%s,\"after_reclose\":%s", boolean(outcome.reopened),
                  boolean(outcome.after_reclose));
    std::printf(",\"final\":%s}}", boolean(outcome.final));
  }
  std::fputs("]}\n", stdout);
  if (std::ferror(stdout) || std::fflush(stdout))
    return diagnose("writing result JSON: %s", std::strerror(errno ? errno : EIO));
  return true;
}
} // namespace

extern "C" U lifetime_generation() noexcept {
  lock(&ledger_mutex);
  const U generation = ledger.requested_generation;
  unlock(&ledger_mutex);
  return generation;
}

extern "C" void lifetime_observe(unsigned stage, U generation, U result,
                                 U effect) noexcept {
  lock(&ledger_mutex);
  ++ledger.count;
  if (generation == 0 || generation > 2 || !ledger.generations[generation].armed) {
    observer_failure("unexpected generation %" PRIu64 " at stage %u", generation, stage);
  } else {
    Generation &record = ledger.generations[generation];
    const unsigned index = record.count++;
    if (index >= trace_size) {
      observer_failure("generation %" PRIu64 " has an extra stage %u", generation, stage);
    } else {
      record.events[index] = {stage, result, effect};
      const unsigned expected_stage = trace[index];
      const Step expected = oracle(expected_stage, generation, record.expected_effect);
      record.expected_effect = expected.effect;
      if (stage != expected_stage)
        observer_failure("generation %" PRIu64 " event %u: expected stage %u, got %u",
                         generation, index, expected_stage, stage);
      if (result != expected.result || effect != expected.effect)
        observer_failure("generation %" PRIu64 " event %u stage %u: expected result/effect "
                         "%" PRIu64 "/%" PRIu64 ", got %" PRIu64 "/%" PRIu64,
                         generation, index, stage, expected.result, expected.effect, result, effect);
    }
  }
  const bool fatal = ledger.failed && ledger.exit_phase;
  unlock(&ledger_mutex);
  // exit_phase is enabled only after all workers joined and both handles closed.
  // No joinable worker or host-side DSO pointer exists when this path is possible.
  if (fatal)
    std::_Exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
  if (argc != 3 || argv[1][0] != '/') {
    diagnose("usage: host absolute-library-path joined|tls|nodelete");
    return EXIT_FAILURE;
  }
  Mode mode;
  if (std::strcmp(argv[2], "joined") == 0)
    mode = Mode::Joined;
  else if (std::strcmp(argv[2], "tls") == 0)
    mode = Mode::Tls;
  else if (std::strcmp(argv[2], "nodelete") == 0)
    mode = Mode::Nodelete;
  else {
    diagnose("unknown lifetime mode: %s", argv[2]);
    return EXIT_FAILURE;
  }
  struct stat status{};
  if (stat(argv[1], &status)) {
    diagnose("stat library: %s", std::strerror(errno));
    return EXIT_FAILURE;
  }
  if (!S_ISREG(status.st_mode) || status.st_ino == 0) {
    diagnose("library must be a regular file with a nonzero inode");
    return EXIT_FAILURE;
  }
  const Identity identity{major(status.st_dev), minor(status.st_dev),
                          static_cast<unsigned long long>(status.st_ino)};
  if (mode == Mode::Nodelete && std::atexit(nodelete_exit_check)) {
    diagnose("registering NODELETE exit checker failed");
    return EXIT_FAILURE;
  }
  Outcome outcomes[2]{};
  const unsigned generations = mode == Mode::Nodelete ? 1 : 2;
  for (unsigned i = 0; i < generations; ++i) {
    if (!run_generation(argv[1], identity, mode, i + 1, outcomes[i]))
      return EXIT_FAILURE;
  }
  if (!print_result(argv[2], mode, outcomes, generations))
    return EXIT_FAILURE;
  if (mode == Mode::Nodelete) {
    lock(&ledger_mutex);
    ledger.verify_nodelete_exit = true;
    ledger.exit_phase = true;
    unlock(&ledger_mutex);
  }
  return EXIT_SUCCESS;
}
