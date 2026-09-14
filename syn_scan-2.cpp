// Compile: g++ -o syn_scan syn_scan.cpp -lpthread
// Run: sudo ./syn_scan <target_ip> <start_port> <end_port>
// Requires: root privileges (raw sockets)

#include <iostream>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <thread>
#include <mutex>
#include <atomic>

class StealthScanner {
private:
    int sock;
    std::string targetIP;
    std::mutex mtx;
    std::vector<int> openPorts;
    std::atomic<int> currentPort{0};
    
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
    StealthScanner(const std::string& ip) : targetIP(ip) {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) { perror("socket"); exit(1); }
        
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    }
    
    bool scanPort(int port, int timeout_ms = 2000) {
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
        tcp->syn = 1;
        tcp->window = htons(65535);
        
        sendto(sock, packet, ip->tot_len, 0, 
               (struct sockaddr*)&target, sizeof(target));
        
        // Wait for response
        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLIN;
        
        int ret = poll(&pfd, 1, timeout_ms);
        if (ret > 0) {
            char response[4096];
            struct sockaddr_in from;
            socklen_t fromlen = sizeof(from);
            recvfrom(sock, response, sizeof(response), 0, 
                    (struct sockaddr*)&from, &fromlen);
            
            struct iphdr* rip = (struct iphdr*)response;
            struct tcphdr* rtcp = (struct tcphdr*)(response + (rip->ihl * 4));
            
            if (rtcp->source == htons(port) && rtcp->syn && rtcp->ack) {
                return true;
            }
        }
        return false;
    }
    
    void scanRange(int startPort, int endPort, int numThreads = 10) {
        std::vector<std::thread> threads;
        
        for (int t = 0; t < numThreads; t++) {
            threads.emplace_back([this, startPort, endPort]() {
                while (true) {
                    int port = currentPort.fetch_add(1);
                    if (port > endPort) break;
                    
                    if (scanPort(port)) {
                        std::lock_guard<std::mutex> lock(mtx);
                        openPorts.push_back(port);
                        std::cout << "[+] Port " << port << " open\n";
                    }
                }
            });
        }
        
        currentPort = startPort;
        for (auto& t : threads) t.join();
    }
    
    std::vector<int> getOpenPorts() { return openPorts; }
    
    ~StealthScanner() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <target_ip> <start_port> <end_port>\n";
        return 1;
    }
    StealthScanner scanner(argv[1]);
    scanner.scanRange(atoi(argv[2]), atoi(argv[3]));
    return 0;
}
