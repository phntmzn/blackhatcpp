// ============================================================
// interpose.cpp — replace open() via __interpose section
// ------------------------------------------------------------
// Compile: clang++ -dynamiclib -std=c++17 -O2 -o interpose.dylib interpose.cpp
// Usage:   DYLD_INSERT_LIBRARIES=./interpose.dylib ./target
// Debug:   DYLD_PRINT_INTERPOSING=1
// ============================================================
#include <cstdio>
#include <fcntl.h>
#include <sys/types.h>

extern "C" int my_open(const char* path, int flags, mode_t mode) {
    std::printf("[interpose] open: %s\n", path);
    return open(path, flags, mode);
}

#define DYLD_INTERPOSE(_repl, _orig) \
    __attribute__((used)) static struct { \
        const void* replacement; \
        const void* replacee; \
    } _interpose_##_orig \
    __attribute__((section("__DATA,__interpose"))) = \
        { reinterpret_cast<const void*>(&_repl), \
          reinterpret_cast<const void*>(&_orig) };

DYLD_INTERPOSE(my_open, open)
