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

    char buf[64] =
