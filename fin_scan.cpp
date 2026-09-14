// ============================================================
// fin_scan.cpp — TCP FIN/XMAS/NULL scan variants
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o fin_scan fin_scan.cpp
// Usage:   sudo ./fin_scan <target_ip> <port> <mode>
//          mode: fin | xmas | null
// ============================================================
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 4) return 1;
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, argv[1], &dst.sin_addr);

    char buf[40] = {0};
    auto* ip = (iphdr*)buf;
    auto* tcp = (tcphdr*)(buf + sizeof(iphdr));
    ip->version = 4; ip->ihl = 5; ip->tot_len = htons(40);
    ip->ttl = 64; ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr("10.0.0.1");
    ip->daddr = dst.sin_addr.s_addr;
    tcp->source = htons(40000);
    tcp->dest = htons(std::atoi(argv[2]));
    tcp->doff = 5;

    if (strcmp(argv[3], "fin") == 0)        tcp->fin = 1;
    else if (strcmp(argv[3], "xmas") == 0) { tcp->fin = tcp->psh = tcp->urg = 1; }
    else if (strcmp(argv[3], "null") == 0)  { /* no flags */ }

    sendto(s, buf, 40, 0, (sockaddr*)&dst, sizeof(dst));
    std::printf("[+] sent %s scan\n", argv[3]);
    return 0;
}
