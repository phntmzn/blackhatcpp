// ============================================================
// inject.cpp — runs code on dylib load via constructor
// ------------------------------------------------------------
// Compile: clang++ -dynamiclib -std=c++17 -O2 -o inject.dylib inject.cpp
// Usage:   DYLD_INSERT_LIBRARIES=./inject.dylib ./target
// Note:    Target must NOT have hardened runtime, library validation,
//          or be SIP-protected. Check with:
//          codesign -dv --entitlements :- ./target
// ============================================================
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <string>

__attribute__((constructor))
static void init() {
    std::fprintf(stderr, "[+] injected into pid %d\n", getpid());
    std::system("id > /tmp/injected_id.txt");
}
