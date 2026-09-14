// Compile: g++ -o fingerprint fingerprint.cpp
// Run: sudo ./fingerprint <target_ip> <port>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>

class TCPFingerprinter {
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
    TCPFingerprinter() {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) { perror("socket"); exit(1); }
    }
    
    void fingerprint(const char* targetIP, int targetPort) {
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(targetPort);
        target.sin_addr.s_addr = inet_addr(targetIP);
        
        char packet[4096];
        struct iphdr* ip = (struct iphdr*)packet;
        struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
        char* options = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
        
        memset(packet, 0, 4096);
        
        // SYN with MSS and Window Scale
        options[0] = 0x02; options[1] = 0x04;
        *(uint16_t*)(options + 2) = htons(1460);
        options[4] = 0x01;
        options[5] = 0x03; options[6] = 0x03;
        options[7] = 0x07;
        
        int optLen = 8;
        
        ip->ihl = 5;
        ip->version = 4;
        ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + optLen;
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP;
        ip->saddr = inet_addr("192.168.1.100");
        ip->daddr = target.sin_addr.s_addr;
        ip->check = checksum(ip, sizeof(struct iphdr));
        
        tcp->source = htons(rand() % 65535);
        tcp->dest = target.sin_port;
        tcp->seq = rand();
        tcp->doff = 5 + (optLen / 4);
        tcp->syn = 1;
        tcp->window = htons(65535);
        
        sendto(sock, packet, ip->tot_len, 0, 
               (struct sockaddr*)&target, sizeof(target));
        
        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLIN;
        
        int ret = poll(&pfd, 1, 2000);
        if (ret > 0) {
            char response[4096];
            struct sockaddr_in from;
            socklen_t fromlen = sizeof(from);
            recvfrom(sock, response, sizeof(response), 0, 
                    (struct sockaddr*)&from, &fromlen);
            
            struct iphdr* rip = (struct iphdr*)response;
            struct tcphdr* rtcp = (struct tcphdr*)(response + (rip->ihl * 4));
            
            std::cout << "TTL: " << (int)rip->ttl << std::endl;
            std::cout << "Window: " << ntohs(rtcp->window) << std::endl;
            std::cout << "Flags: 0x" << std::hex << (int)rtcp->th_flags << std::endl;
        }
    }
    
    ~TCPFingerprinter() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <target_ip> <port>\n";
        return 1;
    }
    TCPFingerprinter fp;
    fp.fingerprint(argv[1], atoi(argv[2]));
    return 0;
}