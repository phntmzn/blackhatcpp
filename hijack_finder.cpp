// ============================================================
// hijack_finder.cpp — discover weak-linked dylib paths
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o hijack_finder hijack_finder.cpp
// Usage:   ./hijack_finder /Applications/Target.app/Contents/MacOS/Target
// ============================================================
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <array>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: %s <binary>\n", argv[0]);
        return 1;
    }

    std::string cmd = "otool -L '";
    cmd += argv[1];
    cmd += "'";

    FILE* f = popen(cmd.c_str(), "r");
    if (!f) return 1;

    std::array<char, 1024> line{};
    while (fgets(line.data(), line.size(), f)) {
        std::string s(line.data());
        if (s.find("@rpath") != std::string::npos ||
            s.find("/usr/local/lib") != std::string::npos) {
            std::printf("[weak?] %s", s.c_str());
        }
    }
    pclose(f);
    return 0;
}
