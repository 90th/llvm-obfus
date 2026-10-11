#define _GNU_SOURCE
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifdef USE_DLOPEN
#include <dlfcn.h>
#else
#include <unistd.h>
#endif

uint64_t oracle_target(uint64_t, uint64_t *);
typedef uint64_t (*target_fn)(uint64_t, uint64_t *);
#ifndef USE_DLOPEN
uint64_t protected_target(uint64_t, uint64_t *);
#endif

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/') {
        fprintf(stderr, "expected absolute deployed image path\n");
        return 2;
    }
    target_fn entry = NULL;
    int status = 0;
#ifdef USE_DLOPEN
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 3;
    }
    dlerror();
    void *address = dlsym(handle, "protected_target");
    const char *error = dlerror();
    Dl_info origin;
    if (error || !address || sizeof(entry) != sizeof(address) ||
        !dladdr(address, &origin) || !origin.dli_fname ||
        strcmp(origin.dli_fname, argv[1]) != 0) {
        fprintf(stderr, "deployed target lookup/path mismatch\n");
        status = 4;
        goto cleanup;
    }
    memcpy(&entry, &address, sizeof(entry));
#else
    char actual_path[4096];
    ssize_t length = readlink("/proc/self/exe", actual_path, sizeof(actual_path) - 1);
    if (length < 0 || (size_t)length >= sizeof(actual_path) - 1) {
        fprintf(stderr, "cannot identify deployed executable\n");
        return 4;
    }
    actual_path[length] = '\0';
    if (strcmp(actual_path, argv[1]) != 0) {
        fprintf(stderr, "deployed executable path mismatch\n");
        return 4;
    }
    target_fn volatile retained_entry = protected_target;
    entry = retained_entry;
#endif
    const uint64_t edges[] = {
        UINT64_C(0), UINT64_C(1), UINT64_C(2), UINT64_MAX,
        UINT64_MAX - UINT64_C(1), UINT64_C(0x8000000000000000),
        UINT64_C(0x7fffffffffffffff), UINT64_C(0x00000000ffffffff),
        UINT64_C(0x0000000100000000), UINT64_C(0xffffffff00000000),
        UINT64_C(0xaaaaaaaaaaaaaaaa), UINT64_C(0x5555555555555555)
    };
    uint64_t state = UINT64_C(0x243f6a8885a308d3);
    uint64_t actual_effect = UINT64_C(0xfedcba9876543210);
    uint64_t expected_effect = actual_effect;
    for (unsigned i = 0; i < 512; ++i) {
        uint64_t input;
        if (i < sizeof(edges) / sizeof(edges[0])) {
            input = edges[i];
        } else {
            state += UINT64_C(0x9e3779b97f4a7c15);
            input = (state ^ (state >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
            input = (input ^ (input >> 27)) * UINT64_C(0x94d049bb133111eb);
            input ^= input >> 31;
        }
        uint64_t expected = oracle_target(input, &expected_effect);
        uint64_t actual = entry(input, &actual_effect);
        if (actual != expected || actual_effect != expected_effect) {
            fprintf(stderr, "mismatch index=%u input=%016" PRIx64
                    " actual=%016" PRIx64 " expected=%016" PRIx64
                    " effect=%016" PRIx64 " expected_effect=%016" PRIx64 "\n",
                    i, input, actual, expected, actual_effect, expected_effect);
            status = 5;
            goto cleanup;
        }
    }
    puts("PACKAGING_NATIVE_OK inputs=512");
cleanup:
    entry = NULL;
#ifdef USE_DLOPEN
    address = NULL;
    if (dlclose(handle) != 0) {
        fprintf(stderr, "dlclose: %s\n", dlerror());
        return 6;
    }
#endif
    return status;
}
