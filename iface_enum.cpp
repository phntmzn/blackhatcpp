// ============================================================
// iface_enum.cpp — list network interfaces & IPs
// ------------------------------------------------------------
// Compile: clang++ -O2 -o iface_enum iface_enum.cpp
// Run:     ./iface_enum
// ============================================================
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstdio>

int main() {
    struct ifaddrs* ifa;
    getifaddrs(&ifa);
    for (auto* p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr) continue;
        int fam = p->ifa_addr->sa_family;
        if (fam != AF_INET && fam != AF_INET6) continue;
        char buf[INET6_ADDRSTRLEN];
        void* src = fam == AF_INET
            ? (void*)&((sockaddr_in*)p->ifa_addr)->sin_addr
            : (void*)&((sockaddr_in6*)p->ifa_addr)->sin6_addr;
        inet_ntop(fam, src, buf, sizeof(buf));
        printf("%s: %s\n", p->ifa_name, buf);
    }
    freeifaddrs(ifa);
    return 0;
}
