// ============================================================
// dyn_interpose.cpp — runtime interposing via dyld API
// ------------------------------------------------------------
// Compile: clang++ -dynamiclib -std=c++17 -O2 -o dyn_interpose.dylib dyn_interpose.cpp
// Usage:   DYLD_INSERT_LIBRARIES=./dyn_interpose.dylib ./target
// ============================================================
#include <mach-o/dyld.h>
#include <cstdio>
#include <unistd.h>

extern "C" int my_close(int fd) {
    std::printf("[interpose] close(%d)\n", fd);
    return close(fd);
}

__attribute__((constructor))
static void init() {
    std::printf("[+] dynamic interpose loaded\n");
}
