// Compile: g++ -o mac_dhcp mac_dhcp.cpp
// Run: sudo ./mac_dhcp <interface> <new_mac>
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
#include <fstream>

class DHCPLeaseMACSpoof {
private:
    int sock;
    std::string iface, newMAC;
    
    bool parseMAC(const std::string& mac, uint8_t* out) {
        return sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                      &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]) == 6;
    }
    
    void releaseDHCPLease() {
        std::cout << "[*] Releasing DHCP lease\n";
        
        // Try dhclient first
        std::string cmd1 = "dhclient -r " + iface + " 2>/dev/null";
        if (system(cmd1.c_str()) != 0) {
            // Try dhcpcd
            std::string cmd2 = "dhcpcd -k " + iface + " 2>/dev/null";
            system(cmd2.c_str());
        }
        
        // Remove old lease files
        std::string lease1 = "/var/lib/dhcp/dhclient." + iface + ".leases";
        std::string lease2 = "/var/lib/dhcpcd/" + iface + "-*.lease";
        
        std::remove(lease1.c_str());
        std::string rm2 = "rm -f " + lease2 + " 2>/dev/null";
        system(rm2.c_str());
        
        sleep(1);
    }
    
    void requestNewLease() {
        std::cout << "[*] Requesting new DHCP lease\n";
        
        // Try dhclient first
        std::string cmd1 = "dhclient " + iface + " &";
        if (system(cmd1.c_str()) != 0) {
            // Fallback to dhcpcd
            std::string cmd2 = "dhcpcd " + iface + " &";
            system(cmd2.c_str());
        }
        
        sleep(3);
        
        // Show new IP
        std::string showIP = "ip addr show " + iface + " | grep 'inet '";
        std::cout << "[*] New IP configuration:\n";
        system(showIP.c_str());
    }
    
public:
    DHCPLeaseMACSpoof(const std::string& i, const std::string& mac)
        : iface(i), newMAC(mac) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) { perror("socket"); exit(1); }
    }
    
    bool setMAC() {
        uint8_t macBytes[6];
        if (!parseMAC(newMAC, macBytes)) return false;
        
        // Step 1: Release DHCP lease
        releaseDHCPLease();
        
        // Step 2: Bring interface down
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        ioctl(sock, SIOCGIFFLAGS, &ifr);
        ifr.ifr_flags &= ~IFF_UP;
        ioctl(sock, SIOCSIFFLAGS, &ifr);
        sleep(1);
        
        // Step 3: Change MAC
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        memcpy(ifr.ifr_hwaddr.sa_data, macBytes, 6);
        
        if (ioctl(sock, SIOCSIFHWADDR, &ifr) < 0) {
            perror("[!] SIOCSIFHWADDR failed");
            return false;
        }
        
        // Step 4: Bring up
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        ioctl(sock, SIOCGIFFLAGS, &ifr);
        ifr.ifr_flags |= IFF_UP;
        ioctl(sock, SIOCSIFFLAGS, &ifr);
        
        std::cout << "[+] MAC changed to: " << newMAC << "\n";
        
        // Step 5: Request fresh DHCP lease
        requestNewLease();
        
        return true;
    }
    
    ~DHCPLeaseMACSpoof() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <new_mac>\n";
        return 1;
    }
    DHCPLeaseMACSpoof spoof(argv[1], argv[2]);
    return spoof.setMAC() ? 0 : 1;
}
