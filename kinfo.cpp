// ============================================================
// kinfo.cpp — dump kernel info via sysctl
// ------------------------------------------------------------
// Compile: clang++ -O2 -o kinfo kinfo.cpp
// Run:     ./kinfo
// ============================================================
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <cstdio>

int main() {
    struct utsname u;
    uname(&u);
    printf("sysname=%s nodename=%s release=%s version=%s machine=%s\n",
           u.sysname, u.nodename, u.release, u.version, u.machine);

    int mib[2] = { CTL_KERN, KERN_BOOTTIME };
    struct timeval tv;
    size_t sz = sizeof(tv);
    if (sysctl(mib, 2, &tv, &sz, nullptr, 0) == 0)
        printf("boottime=%ld\n", (long)tv.tv_sec);

    char buf[256]; sz = sizeof(buf);
    if (sysctl((int[]){CTL_KERN, KERN_OSVERSION}, 2, buf, &sz, nullptr, 0) == 0)
        printf("osversion=%s\n", buf);
    return 0;
}
