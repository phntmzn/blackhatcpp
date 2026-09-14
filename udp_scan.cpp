// ============================================================
// udp_scan.cpp — UDP port scanner with ICMP feedback
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o udp_scan udp_scan.cpp
// Usage:   sudo ./udp_scan <target_ip> <port_start> <port_end>
// ============================================================
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 4) return 1;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, argv[1], &dst.sin_addr);
    int start = std::atoi(argv[2]), end = std::atoi(argv[3]);

    char probe[1] = {0};
    for (int p = start; p <= end; p++) {
        dst.sin_port = htons(p);
        sendto(s, probe, 1, 0, (sockaddr*)&dst, sizeof(dst));
        std::printf("sent UDP %d\n", p);
    }
    return 0;
}
