// Compile: g++ -o mac_reset mac_reset.cpp
// Run: sudo ./mac_reset <interface> <new_mac>
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

class InterfaceResetMACSpoof {
private:
    int sock;
    std::string iface, newMAC;
    
    bool parseMAC(const std::string& mac, uint8_t* out) {
        return sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                      &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]) == 6;
    }
    
    void resetDriver() {
        // Try to reset driver via sysfs
        std::string unbindPath = "/sys/bus/pci/drivers/*/unbind";
        // This would need actual PCI address - skip in this demo
    }
    
    void restartNetworkServices() {
        std::cout << "[*] Restarting network services\n";
        
        // Detect and restart the right service
        if (system("systemctl is-active --quiet NetworkManager") == 0) {
            system("systemctl restart NetworkManager 2>/dev/null");
            std::cout << "[*] Restarted NetworkManager\n";
        } else if (system("systemctl is-active --quiet systemd-networkd") == 0) {
            system("systemctl restart systemd-networkd 2>/dev/null");
            std::cout << "[*] Restarted systemd-networkd\n";
        } else if (system("systemctl is-active --quiet networking") == 0) {
            system("systemctl restart networking 2>/dev/null");
            std::cout << "[*] Restarted networking\n";
        }
        
        // Also restart dhclient
        std::string dhclient = "dhclient -r " + iface + " 2>/dev/null";
        system(dhclient.c_str());
        sleep(1);
        std::string dhclientUp = "dhclient " + iface + " 2>/dev/null &";
        system(dhclientUp.c_str());
    }
    
public:
    InterfaceResetMACSpoof(const std::string& i, const std::string& mac)
        : iface(i), newMAC(mac) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) { perror("socket"); exit(1); }
    }
    
    bool setMAC() {
        uint8_t macBytes[6];
        if (!parseMAC(newMAC, macBytes)) return false;
        
        // 1. Bring down
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        ioctl(sock, SIOCGIFFLAGS, &ifr);
        ifr.ifr_flags &= ~IFF_UP;
        ioctl(sock, SIOCSIFFLAGS, &ifr);
        
        sleep(1);
        
        // 2. Change MAC
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        memcpy(ifr.ifr_hwaddr.sa_data, macBytes, 6);
        
        if (ioctl(sock, SIOCSIFHWADDR, &ifr) < 0) {
            perror("[!] MAC change failed");
            // Try bringing up anyway
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
            ioctl(sock, SIOCGIFFLAGS, &ifr);
            ifr.ifr_flags |= IFF_UP;
            ioctl(sock, SIOCSIFFLAGS, &ifr);
            return false;
        }
        
        // 3. Bring up
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        ioctl(sock, SIOCGIFFLAGS, &ifr);
        ifr.ifr_flags |= IFF_UP;
        ioctl(sock, SIOCSIFFLAGS, &ifr);
        
        std::cout << "[+] MAC set: " << newMAC << "\n";
        
        // 4. Restart network services to refresh
        restartNetworkServices();
        
        return true;
    }
    
    ~InterfaceResetMACSpoof() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <new_mac>\n";
        return 1;
    }
    InterfaceResetMACSpoof spoof(argv[1], argv[2]);
    return spoof.setMAC() ? 0 : 1;
}
