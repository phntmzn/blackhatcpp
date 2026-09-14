// ============================================================
// dns_axfr.cpp — attempt TCP AXFR zone transfer
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o dns_axfr dns_axfr.cpp
// Usage:   ./dns_axfr <domain> <ns_ip>
// ============================================================
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 3) return 1;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    inet_pton(AF_INET, argv[2], &dst.sin_addr);
    if (connect(s, (sockaddr*)&dst, sizeof(dst)) < 0) return 1;

    char pkt[512] = {0};
    int len = 2; // skip 2-byte length prefix initially
    pkt[len++] = 0x12; pkt[len++] = 0x34;
    pkt[len++] = 0x00; pkt[len++] = 0x00;
    pkt[len++] = 0x00; pkt[len++] = 0x01;
    pkt[len++] = 0x00; pkt[len++] = 0x00;
    pkt[len++] = 0x00; pkt[len++] = 0x00;
    pkt[len++] = 0x00; pkt[len++] = 0x00;

    const char* d = argv[1];
    char label[64]; int l = 0;
    while (*d) {
        if (*d == '.') { pkt[len++] = l; memcpy(pkt + len, label, l); len += l; l = 0; }
        else label[l++] = *d;
        d++;
    }
    if (l) { pkt[len++] = l; memcpy(pkt + len, label, l); len += l; }
    pkt[len++] = 0;
    pkt[len++] = 0x00; pkt[len++] = 0xFC; // AXFR
    pkt[len++] = 0x00; pkt[len++] = 0x01;

    uint16_t plen = htons(len - 2);
    memcpy(pkt, &plen, 2);
    send(s, pkt, len, 0);

    char resp[4096];
    int n = recv(s, resp, sizeof(resp), 0);
    std::printf("[+] got %d bytes\n", n);
    return 0;
}
