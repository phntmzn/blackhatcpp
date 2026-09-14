// ============================================================
// reexport.cpp — re-export original library for hijacking
// ------------------------------------------------------------
// Compile: clang++ -dynamiclib -std=c++17 -O2 -o reexport.dylib reexport.cpp \
//          -Wl,-reexport_library,"/path/to/original.dylib"
// Note:    Replace /path/to/original.dylib with the real library.
// ============================================================
#include <cstdio>

__attribute__((constructor))
static void init() {
    std::fprintf(stderr, "[+] hijack dylib loaded\n");
}
