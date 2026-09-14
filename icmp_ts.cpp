// ============================================================
// icmp_ts.cpp — ICMP timestamp request
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o icmp_ts icmp_ts.cpp
// Usage:   sudo ./icmp_ts <target_ip>
// ============================================================
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

static uint16_t csum(const void* d, int n) {
    const uint16_t* p = (const uint16_t*)d; uint32_t s = 0;
    while (n > 1) { s += *p++; n -= 2; }
    if (n) s += *(const uint8_t*)p;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return ~s;
}

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, argv[1], &dst.sin_addr);

    char buf[64] = {0};
    auto* icmp = (icmphdr*)buf;
    icmp->type = 13; // ICMP_TIMESTAMP
    icmp->code = 0;
    icmp->un.echo.id = getpid() & 0xffff;
    icmp->un.echo.sequence = 1;
    uint32_t now = time(nullptr) + 2208988800UL; // NTP epoch
    memcpy(buf + 8, &now, 4);
    icmp->checksum = csum(buf, sizeof(icmphdr) + 12);

    sendto(s, buf, sizeof(icmphdr) + 12, 0, (sockaddr*)&dst, sizeof(dst));
    std::printf("[+] ICMP timestamp sent\n");
    return 0;
}
