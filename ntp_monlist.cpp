// ============================================================
// ntp_monlist.cpp — NTP mode 6 monlist amplification test
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o ntp_monlist ntp_monlist.cpp
// Usage:   ./ntp_monlist <server_ip>
// ============================================================
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(123);
    inet_pton(AF_INET, argv[1], &dst.sin_addr);

    // NTP mode 6, request code 42 (MON_GETLIST_1)
    uint8_t pkt[48] = {0};
    pkt[0] = 0x16; // LI=0 VN=2 Mode=6
    pkt[1] = 0;    // response bit clear
    pkt[2] = 0; pkt[3] = 1; // sequence
    pkt[4] = 0;    // implementation
    pkt[5] = 42;   // request code

    sendto(s, pkt, sizeof(pkt), 0, (sockaddr*)&dst, sizeof(dst));
    std::printf("[+] NTP monlist sent\n");
    return 0;
}
