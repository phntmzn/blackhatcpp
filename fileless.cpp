// ============================================================
// fileless.cpp — in-memory shellcode execution via mmap
// ------------------------------------------------------------
// Compile: clang++ -O2 -o fileless fileless.cpp
// Run:    ./fileless
// Note:   On hardened runtime, mprotect(PROT_EXEC) may fail
//          unless com.apple.security.cs.allow-jit or
//          allow-unsigned-executable-memory entitlement present.
// ============================================================
#include <sys/mman.h>
#include <cstring>

int main() {
    unsigned char sc[] = { 0x90, 0x90, 0xC3 }; // NOP; NOP; RET

    void* m = mmap(nullptr, sizeof(sc),
                   PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    memcpy(m, sc, sizeof(sc));
    mprotect(m, sizeof(sc), PROT_READ | PROT_EXEC);
    ((void(*)())m)();
    return 0;
}
