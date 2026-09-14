// ============================================================
// sandbox_check.cpp — detect if running under App Sandbox
// ------------------------------------------------------------
// Compile: clang++ -O2 -o sandbox_check sandbox_check.cpp -framework Security
// Run:     ./sandbox_check
// ============================================================
#include <Security/Security.h>
#include <cstdio>
#include <cstdlib>

int main() {
    // Try to read a forbidden path
    const char* home = getenv("HOME");
    char p[512];
    snprintf(p, sizeof(p), "%s/Library/Safari/History.db", home);
    FILE* f = fopen(p, "rb");
    printf("safari history readable: %s\n", f ? "yes" : "no");
    if (f) fclose(f);
    return 0;
}
