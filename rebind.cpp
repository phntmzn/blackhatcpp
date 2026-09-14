// ============================================================
// rebind.cpp — rebind imported symbols (fishhook style)
// ------------------------------------------------------------
// Compile: clang++ -dynamiclib -std=c++17 -O2 -o rebind.dylib rebind.cpp
// Usage:   DYLD_INSERT_LIBRARIES=./rebind.dylib ./target
// ============================================================
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>
#include <mach-o/loader.h>
#include <cstdio>
#include <cstring>

extern "C" int rebind_symbol(const char* name, void* new_impl) {
    const mach_header_64* header = nullptr;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char* imgname = _dyld_get_image_name(i);
        if (!std::strstr(imgname, "/")) continue;
        header = reinterpret_cast<const mach_header_64*>(_dyld_get_image_header(i));
        break;
    }
    if (!header) return -1;
    (void)name; (void)new_impl;
    return -1;
}

__attribute__((constructor))
static void init() {
    std::printf("[+] rebind loaded\n");
}
