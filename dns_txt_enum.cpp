// ============================================================
// dns_txt_enum.cpp — enumerate TXT records
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o dns_txt_enum dns_txt_enum.cpp
// Usage:   ./dns_txt_enum <domain> <resolver>
// ============================================================
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 3) return 1;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    inet_pton(AF_INET, argv[2], &dst.sin_addr);

    char pkt[512] = {0};
    int len = 0;
    pkt[len++] = 0x12; pkt[len++] = 0x34;
    pkt[len++] = 0x01; pkt[len++] = 0x00; // RD
    pkt[len++] = 0x00; pkt[len++] = 0x01;
    pkt[len++] = 0x00; pkt[len++] = 0x00;
    pkt[len++] = 0x00; pkt[len++] = 0x00;
    pkt[len++] = 0x00; pkt[len++] = 0x00;

    const char* d = argv[1];
    char label[64];
    int l = 0;
    while (*d) {
        if (*d == '.') { pkt[len++] = l; memcpy(pkt + len, label, l); len += l; l = 0; }
        else label[l++] = *d;
        d++;
    }
    if (l) { pkt[len++] = l; memcpy(pkt + len, label, l); len += l; }
    pkt[len++] = 0;
    pkt[len++] = 0x00; pkt[len++] = 0x10; // TXT
    pkt[len++] = 0x00; pkt[len++] = 0x01;

    sendto(s, pkt, len, 0, (sockaddr*)&dst, sizeof(dst));
    std::printf("[+] TXT query sent\n");
    return 0;
}
