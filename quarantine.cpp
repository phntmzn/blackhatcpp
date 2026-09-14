// ============================================================
// quarantine.cpp — read com.apple.quarantine xattr
// ------------------------------------------------------------
// Compile: clang++ -O2 -o quarantine quarantine.cpp
// Usage:   ./quarantine <file>
// ============================================================
#include <sys/xattr.h>
#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    char buf[1024];
    ssize_t n = getxattr(argv[1], "com.apple.quarantine", buf, sizeof(buf), 0, 0);
    if (n < 0) { printf("no quarantine xattr\n"); return 0; }
    printf("quarantine: %.*s\n", (int)n, buf);
    return 0;
}
