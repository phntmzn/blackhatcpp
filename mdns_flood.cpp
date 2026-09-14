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
        0x00,0x00, 0x00,0x00, 0x00,0x01, 0x00,0x00, 0x
