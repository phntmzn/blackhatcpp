// ============================================================
// keepalive_probe.cpp — probe TCP keepalive handling
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o keepalive_probe keepalive_probe.cpp
// Usage:   sudo ./keepalive_probe <src> <dst> <sport> <dport>
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
    if (argc < 5) return 1;
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, argv[2], &dst.sin_addr);

    char buf[40] = {0};
    auto* ip = (iphdr*)buf;
    auto* tcp = (tcphdr*)(buf + sizeof(iphdr));
    ip->version = 4; ip->ihl = 5; ip->tot_len = htons(40);
    ip->ttl = 64; ip->protocol = IPPROTO_TCP;
    inet_pton(AF_INET, argv[1], &ip->saddr);
    ip->daddr = dst.sin_addr.s_addr;
    ip->check = csum(ip, sizeof(iphdr));

    tcp->source = htons(std::atoi(argv[3]));
    tcp->dest = htons(std::atoi(argv[4]));
    tcp->seq = htonl(1);
    tcp->ack_seq = htonl(1);
    tcp->doff = 5;
    tcp->ack = 1;
    tcp->window = htons(1); // zero-ish window to trigger keepalive

    for (int i = 0; i < 10; i++) {
        sendto(s, buf, 40, 0, (sockaddr*)&dst, sizeof(dst));
        sleep(1);
    }
    std::printf("[+] keepalive probes sent\n");
    return 0;
}
