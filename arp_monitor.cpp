// Compile: g++ -o arp_monitor arp_monitor.cpp
// Run: sudo ./arp_monitor <interface>
// Requires: root privileges, libpcap optional

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <map>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <unistd.h>

class ARPMonitor {
private:
    int sock;
    std::string interface;
    std::map<std::string, std::string> arpTable;
    
public:
    ARPMonitor(const std::string& iface) : interface(iface) {
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (sock < 0) { perror("socket"); exit(1); }
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(interface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        
        if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
            perror("bind");
            exit(1);
        }
    }
    
    void monitor() {
        char buffer[65536];
        
        while (true) {
            int bytes = recv(sock, buffer, sizeof(buffer), 0);
            if (bytes < 42) continue;
            
            struct ether_arp* arp = (struct ether_arp*)(buffer + 14);
            
            if (ntohs(arp->arp_op) == ARPOP_REPLY) {
                char ip[INET_ADDRSTRLEN];
                char mac[18];
                
                inet_ntop(AF_INET, arp->arp_spa, ip, sizeof(ip));
                snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                         arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
                         arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
                
                std::string ipStr(ip);
                std::string macStr(mac);
                
                if (arpTable.find(ipStr) != arpTable.end()) {
                    if (arpTable[ipStr] != macStr) {
                        std::cout << "[!] Possible ARP poisoning detected!\n";
                        std::cout << "    IP: " << ipStr << "\n";
                        std::cout << "    Old MAC: " << arpTable[ipStr] << "\n";
                        std::cout << "    New MAC: " << macStr << "\n";
                    }
                }
                
                arpTable[ipStr] = macStr;
            }
        }
    }
    
    ~ARPMonitor() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        return 1;
    }
    ARPMonitor monitor(argv[1]);
    monitor.monitor();
    return 0;
}