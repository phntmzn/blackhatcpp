// ============================================================
// ack_scan.cpp — TCP ACK scan to map firewall rules
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o ack_scan ack_scan.cpp
// Usage:   sudo ./ack_scan <target_ip> <port_start> <port_end>
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
    inet_pton(AF_INET, argv[1], &dst.sin_addr);
    int start = std::atoi(argv[2]), end = std::atoi(argv[3]);

    for (int p = start; p <= end; p++) {
        char buf[40] = {0};
        auto* ip = (iphdr*)buf;
        auto* tcp = (tcphdr*)(buf + sizeof(iphdr));
        ip->version = 4; ip->ihl = 5; ip->tot_len = htons(40);
        ip->ttl = 64; ip->protocol = IPPROTO_TCP;
        ip->saddr = inet_addr("10.0.0.1");
        ip->daddr = dst.sin_addr.s_addr;
        ip->check = csum(ip, sizeof(iphdr));
        tcp->source = htons(40000 + (p % 20000));
        tcp->dest = htons(p);
        tcp->doff = 5;
        tcp->ack = 1;
        sendto(s, buf, 40, 0, (sockaddr*)&dst, sizeof(dst));
    }
    std::printf("[+] sent ACK probes\n");
    return 0;
}
