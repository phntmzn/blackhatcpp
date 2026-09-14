// ============================================================
// antidebug.cpp — detects debugger via sysctl P_TRACED
// ------------------------------------------------------------
// Compile: clang++ -O2 -o antidebug antidebug.cpp
// Run:    ./antidebug
// ============================================================
#include <sys/sysctl.h>
#include <unistd.h>
#include <cstdio>

int main() {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    struct kinfo_proc info;
    size_t size = sizeof(info);
    sysctl(mib, 4, &info, &size, nullptr, 0);

    bool traced = (info.kp_proc.p_flag & P_TRACED) != 0;
    puts(traced ? "DEB" : "CLEAN");
    return 0;
}
