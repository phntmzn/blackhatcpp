// ============================================================
// tcp_ts_probe.cpp — TCP timestamp option fingerprint
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o tcp_ts_probe tcp_ts_probe.cpp
// Usage:   sudo ./tcp_ts_probe <src> <dst> <dport>
// ============================================================
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
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
    auto* tcp = (tcphdr*)(buf + sizeof(iphdr));
    ip->version = 4; ip->ihl = 5; ip->tot_len = htons(52);
    ip->ttl = 64; ip->protocol = IPPROTO_TCP;
    inet_pton(AF_INET, argv[1], &ip->saddr);
    ip->daddr = dst.sin_addr.s_addr;
    ip->check = csum(ip, sizeof(iphdr));

    tcp->source = htons(40000);
    tcp->dest = htons(std::atoi(argv[3]));
    tcp->doff = 8; // 32 bytes (NOP, NOP, TS, SACK-permitted)
    tcp->syn = 1;
    tcp->window = htons(65535);

    uint8_t* opt = (uint8_t*)(buf + sizeof(iphdr) + sizeof(tcphdr));
    opt[0] = 1; opt[1] = 1;              // NOP NOP
    opt[2] = 8; opt[3] = 10;             // TS kind, len
    opt[4] = 0x11; opt[5] = 0x22; opt[6] = 0x33; opt[7] = 0x44;
    opt[8] = 0; opt[9] = 0; opt[10] = 0; opt[11] = 0;
    opt[12] = 4; opt[13] = 2;            // SACK permitted

    sendto(s, buf, 52, 0, (sockaddr*)&dst, sizeof(dst));
    std::printf("[+] timestamp probe sent\n");
    return 0;
}
