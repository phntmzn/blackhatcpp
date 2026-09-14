// Compile: g++ -o fin_scan fin_scan.cpp
// Run: sudo ./fin_scan <target_ip> <port>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

class FINScanner {
private:
    int sock;
    std::string targetIP;
    
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
    FINScanner(const std::string& ip) : targetIP(ip) {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) { perror("socket"); exit(1); }
    }
    
    bool scan(int port) {
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        target.sin_addr.s_addr = inet_addr(targetIP.c_str());
        
        char packet[4096];
        struct iphdr* ip = (struct iphdr*)packet;
        struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
        
        memset(packet, 0, 4096);
        
        ip->ihl = 5;
        ip->version = 4;
        ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP;
        ip->saddr = inet_addr("192.168.1.100");
        ip->daddr = target.sin_addr.s_addr;
        ip->check = checksum(ip, sizeof(struct iphdr));
        
        tcp->source = htons(rand() % 65535);
        tcp->dest = target.sin_port;
        tcp->seq = rand();
        tcp->doff = 5;
        tcp->fin = 1;
        tcp->window = htons(0);
        
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
            
            if (rtcp->rst) return false;  // Port closed
        }
        return true;  // Port open or filtered
    }
    
    ~FINScanner() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <target_ip> <port>\n";
        return 1;
    }
    FINScanner scanner(argv[1]);
    if (scanner.scan(atoi(argv[2]))) {
        std::cout << "Port " << argv[2] << " is open or filtered\n";
    } else {
        std::cout << "Port " << argv[2] << " is closed\n";
    }
    return 0;
}