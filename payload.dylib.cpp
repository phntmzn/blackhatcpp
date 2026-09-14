// ============================================================
// payload.dylib.cpp — runs code on dlopen/load
// ------------------------------------------------------------
// Compile: clang++ -dynamiclib -O2 -o payload.dylib payload.dylib.cpp -framework CoreFoundation
// Inject:  dlopen("payload.dylib", RTLD_NOW)
// ============================================================
#include <cstdio>
#include <unistd.h>

__attribute__((constructor))
static void on_load() {
    printf("[+] payload loaded in pid %d\n", getpid());
    // Your post-exploitation code here
}
