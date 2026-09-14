// ============================================================
// mdns_flood.cpp — flood .local mDNS queries
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o mdns_flood mdns_flood.cpp
// Usage:   sudo ./mdns_flood <count>
// ============================================================
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(5353);
    inet_pton(AF_INET, "224.0.0.251", &dst.sin_addr);

    // Minimal mDNS query for "_services._dns-sd._udp.local"
    uint8_t pkt[] = {
        0x00,0x00, 0x00,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
        0x09,'_','s','e','r','v','i','c','e','s',
        0x07,'_','d','n','s','-','s','d',
        0x04,'_','u','d','p',
        0x05,'l','o','c','a','l', 0x00,
        0x00,0x0c, 0x00,0x01
    };

    int n = std::atoi(argv[1]);
    for (int i = 0; i < n; i++)
        sendto(s, pkt, sizeof(pkt), 0, (sockaddr*)&dst, sizeof(dst));
    std::printf("[+] sent %d mDNS queries\n", n);
    return 0;
}
