// ============================================================
// tcc_probe.cpp — check which TCC services are accessible
// ------------------------------------------------------------
// Compile: clang++ -dynamiclib -std=c++17 -O2 -o tcc_probe.dylib tcc_probe.cpp
// Usage:   DYLD_INSERT_LIBRARIES=./tcc_probe.dylib ./any_app
// ============================================================
#include <cstdio>
#include <cstdlib>
#include <string>

__attribute__((constructor))
static void probe() {
    const char* home = std::getenv("HOME");
    if (!home) return;
    std::string base = home;

    auto check = [](const std::string& label, const std::string& path) {
        FILE* f = std::fopen(path.c_str(), "rb");
        std::printf("[TCC] %s: %s\n", label.c_str(), f ? "ACCESSIBLE" : "denied");
        if (f) std::fclose(f);
    };

    check("Safari History", base + "/Library/Safari/History.db");
    check("Messages",       base + "/Library/Messages/chat.db");
    std::fflush(stdout);
}
