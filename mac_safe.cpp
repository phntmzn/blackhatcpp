// Compile: g++ -o mac_safe mac_safe.cpp
// Run: sudo ./mac_safe <interface> <new_mac>
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

class SafeMACSpoof {
private:
    int sock;
    std::string iface, newMAC;
    
    bool parseMAC(const std::string& mac, uint8_t* out) {
        return sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                      &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]) == 6;
    }
    
    bool setInterfaceState(bool up) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) return false;
        
        if (up) {
            ifr.ifr_flags |= IFF_UP;
        } else {
            ifr.ifr_flags &= ~IFF_UP;
        }
        
        return ioctl(sock, SIOCSIFFLAGS, &ifr) == 0;
    }
    
public:
    SafeMACSpoof(const std::string& i, const std::string& mac)
        : iface(i), newMAC(mac) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) { perror("socket"); exit(1); }
    }
    
    bool setMAC() {
        uint8_t macBytes[6];
        if (!parseMAC(newMAC, macBytes)) {
            std::cerr << "[!] Invalid MAC format\n";
            return false;
        }
        
        // Step 1: Bring interface down
        std::cout << "[*] Bringing " << iface << " down\n";
        if (!setInterfaceState(false)) {
            perror("[!] Failed to bring interface down");
            return false;
        }
        
        usleep(100000);  // 100ms
        
        // Step 2: Change MAC
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        memcpy(ifr.ifr_hwaddr.sa_data, macBytes, 6);
        
        if (ioctl(sock, SIOCSIFHWADDR, &ifr) < 0) {
            perror("[!] MAC change failed");
            setInterfaceState(true);
            return false;
        }
        
        // Step 3: Bring interface back up
        std::cout << "[*] Bringing " << iface << " up\n";
        if (!setInterfaceState(true)) {
            perror("[!] Failed to bring interface up");
            return false;
        }
        
        std::cout << "[+] MAC set to " << newMAC << " on " << iface << "\n";
        return true;
    }
    
    ~SafeMACSpoof() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <new_mac>\n";
        return 1;
    }
    SafeMACSpoof spoof(argv[1], argv[2]);
    return spoof.setMAC() ? 0 : 1;
}
