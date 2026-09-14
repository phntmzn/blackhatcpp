// ============================================================
// dlopen_hook.cpp — interpose dlopen to log library loads
// ------------------------------------------------------------
// Compile: clang++ -dynamiclib -std=c++17 -O2 -o dlopen_hook.dylib dlopen_hook.cpp
// Usage:   DYLD_INSERT_LIBRARIES=./dlopen_hook.dylib ./target
// ============================================================
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <cstdio>

static void* (*orig_dlopen)(const char*, int) = nullptr;

extern "C" void* my_dlopen(const char* path, int mode) {
    std::printf("[load] %s\n", path);
    std::fflush(stdout);
    return orig_dlopen(path, mode);
}

__attribute__((constructor))
static void setup() {
    orig_dlopen = reinterpret_cast<void*(*)(const char*, int)>(
        dlsym(RTLD_NEXT, "dlopen"));
}
