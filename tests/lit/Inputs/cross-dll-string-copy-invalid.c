// This fixture deliberately avoids system headers so unsupported-target cases
// test the export gate rather than failing in a foreign target's SDK headers.
typedef unsigned int uint32_t;
typedef __SIZE_TYPE__ size_t;
#define SOURCE __attribute__((used, annotate("obf.string_copy.v1:exchange_copy_v1:1")))

#if COPY_PE_BAD_CASE == 2
SOURCE __declspec(dllexport) const char invalid_source[] = "exported producer data";
#else
SOURCE static const char invalid_source[] = "private producer data";
#endif

#if COPY_PE_BAD_CASE == 1
__declspec(dllimport)
#else
__declspec(dllexport)
#endif
int exchange_copy_v1(uint32_t, char *, size_t, size_t *);
__attribute__((used)) static void *keep_accessor = (void *)&exchange_copy_v1;
