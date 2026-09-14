// ============================================================
// dyld_hijack.cpp — run payload via DYLD_INSERT_LIBRARIES
// ------------------------------------------------------------
// Compile payload: clang++ -dynamiclib -O2 -o hook.dylib dyld_payload.cpp
// Launch: DYLD_INSERT_LIBRARIES=./hook.dylib /path/to/victim
// Note:   Requires target NOT signed with hardened runtime.
//          SIP-protected binaries reject this.
// ============================================================
#include <cstdio>
#include <unistd.h>

__attribute__((constructor))
static void init() {
    fprintf(stderr, "[+] hooked pid %d\n", getpid());
}
