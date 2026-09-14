// ============================================================
// timer_agent.cpp — periodic LaunchAgent via StartInterval
// ------------------------------------------------------------
// Compile: clang++ -O2 -o timer_agent timer_agent.cpp
// Run:     ./timer_agent
// ============================================================
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

int main() {
    char path[4096]; uint32_t sz = sizeof(path);
    _NSGetExecutablePath(path, &sz);
    const char* home = getenv("HOME");

    std::string plist = R"(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.timer.agent</string>
  <key>ProgramArguments</key><array><string>)" + std::string(path) + R"(</string></array>
  <key>StartInterval</key><integer>60</integer>
</dict></plist>)";

    std::string out = std::string(home) + "/Library/LaunchAgents/com.timer.agent.plist";
    std::ofstream(out) << plist;
    return 0;
}
