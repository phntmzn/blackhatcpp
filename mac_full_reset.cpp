// Compile: g++ -o mac_full_reset mac_full_reset.cpp
// Run: sudo ./mac_full_reset <interface> <new_mac>
// Requires: root privileges

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_arp.h>

class FullMACReset {
private:
    int sock;
    std::string iface, newMAC;
    
    bool parseMAC(const std::string& mac, uint8_t* out) {
        return sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                      &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]) == 6;
    }
    
    void clearARPTable() {
        std::cout << "[*] Clearing ARP table\n";
        system("ip neigh flush all 2>/dev/null");
        system("arp -d 2>/dev/null");
    }
    
    void resetDHCPv6DUID() {
        std::cout << "[*] Resetting DHCPv6 DUID\n";
        
        // Common locations for DHCPv6 DUID
        std::string duidPaths[] = {
            "/var/lib/dhcp6c.leases",
            "/var/lib/dhcpcd6.duid",
            "/var/lib/NetworkManager/dhclient6-*.lease",
            "/var/lib/networkd/dhcp6-duid",
        };
        
        for (const auto& path : duidPaths) {
            std::string cmd = "rm -f " + path + " 2>/dev/null";
            system(cmd.c_str());
        }
        
        // NetworkManager connection DUID is derived from MAC, so it regenerates
    }
    
    void clearNeighborCache() {
        std::cout << "[*] Clearing IPv6 neighbor cache\n";
        system("ip -6 neigh flush all 2>/dev/null");
    }
    
    void clearDNS() {
        std::cout << "[*] Flushing DNS cache\n";
        system("systemd-resolve --flush-caches 2>/dev/null");
        system("resolvectl flush-caches 2>/dev/null");
    }
    
public:
    FullMACReset(const std::string& i, const std::string& mac)
        : iface(i), newMAC(mac) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) { perror("socket"); exit(1); }
    }
    
    bool setMAC() {
        uint8_t macBytes[6];
        if (!parseMAC(newMAC, macBytes)) return false;
        
        std::cout << "[*] Full identity reset sequence\n\n";
        
        // 1. Release DHCP leases
        std::string release = "dhclient -r " + iface + " 2>/dev/null";
        system(release.c_str());
        release = "dhcpcd -k " + iface + " 2>/dev/null";
        system(release.c_str());
        
        // 2. Clear ARP/neighbor tables
        clearARPTable();
        clearNeighborCache();
        
        // 3. Reset DHCPv6 DUID
        resetDHCPv6DUID();
        
        // 4. Bring interface down
        std::cout << "[*] Bringing interface down\n";
        std::string down = "ip link set " + iface + " down";
        system(down.c_str());
        sleep(1);
        
        // 5. Change MAC
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        memcpy(ifr.ifr_hwaddr.sa_data, macBytes, 6);
        
        if (ioctl(sock, SIOCSIFHWADDR, &ifr) < 0) {
            perror("[!] SIOCSIFHWADDR failed");
            return false;
        }
        std::cout << "[+] MAC changed: " << newMAC << "\n";
        
        // 6. Bring up
        std::cout << "[*] Bringing interface up\n";
        std::string up = "ip link set " + iface + " up";
        system(up.c_str());
        sleep(1);
        
        // 7. Flush DNS cache
        clearDNS();
        
        // 8. Request new DHCP lease
        std::cout << "[*] Requesting new DHCP lease\n";
        std::string dhclient = "dhclient " + iface + " &";
        system(dhclient.c_str());
        sleep(3);
        
        // 9. Show new state
        std::cout << "\n[*] New interface state:\n";
        std::string show = "ip addr show " + iface;
        system(show.c_str());
        
        std::cout << "\n[+] Full identity reset complete\n";
        return true;
    }
    
    ~FullMACReset() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <new_mac>\n";
        return 1;
    }
    FullMACReset reset(argv[1], argv[2]);
    return reset.setMAC() ? 0 : 1;
}
