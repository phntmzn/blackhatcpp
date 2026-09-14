// ============================================================
// persist_daemon.cpp — /Library/LaunchDaemons (root-level)
// ------------------------------------------------------------
// Compile: clang++ -O2 -o persist_daemon persist_daemon.cpp
// Run:     sudo ./persist_daemon
// Note:    Runs at boot as root. Requires sudo.
// ============================================================
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

int main() {
    char path[4096];
    uint32_t sz = sizeof(path);
    _NSGetExecutablePath(path, &sz);

    std::string plist = R"(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.sys.daemon</string>
  <key>ProgramArguments</key>
  <array><string>)" + std::string(path) + R"(</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>)";

    std::ofstream f("/Library/LaunchDaemons/com.sys.daemon.plist");
    f << plist;
    system("launchctl load -w /Library/LaunchDaemons/com.sys.daemon.plist");
    return 0;
}
