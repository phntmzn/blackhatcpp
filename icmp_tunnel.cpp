// ============================================================
// icmp_tunnel.cpp — tunnel data in ICMP echo payloads
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o icmp_tunnel icmp_tunnel.cpp
// Usage:   sudo ./icmp_tunnel <dst_ip> <data>
// ============================================================
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static uint16_t csum(const void* d, int n) {
    const uint16_t* p = (const uint16_t*)d; uint32_t s = 0;
    while (n > 1) { s += *p++; n -= 2; }
    if (n) s += *(const uint8_t*)p;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return ~s;
}

int main(int argc, char** argv) {
    if (argc < 3) return 1;
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, argv[1], &dst.sin_addr);

    const char* data = argv[2];
    int dlen = strlen(data);
    char buf[64 + 1024] = {0};
    auto* icmp = (icmphdr*)buf;
    icmp->type = 8;
    icmp->code = 0;
    icmp->un.echo.id = 0x4141;
    icmp->un.echo.sequence = 1;
    memcpy(buf + sizeof(icmphdr), data, dlen);
    icmp->checksum = csum(buf, sizeof(icmphdr) + dlen);

    sendto(s, buf, sizeof(icmphdr) + dlen, 0, (sockaddr*)&dst, sizeof(dst));
    std::printf("[+] tunneled %d bytes\n", dlen);
    return 0;
}
