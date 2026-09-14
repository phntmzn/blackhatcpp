// Compile: g++ -o mac_wifi mac_wifi.cpp
// Run: sudo ./mac_wifi <interface> <new_mac>
// Requires: root privileges, WiFi interface

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

class WiFiMACSpoof {
private:
    int sock;
    std::string iface, newMAC;
    
    void macToStr(const uint8_t* mac, char* out) {
        snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    
    bool parseMAC(const std::string& mac, uint8_t* out) {
        return sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                      &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]) == 6;
    }
    
public:
    WiFiMACSpoof(const std::string& i, const std::string& mac)
        : iface(i), newMAC(mac) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) { perror("socket"); exit(1); }
    }
    
    bool setMAC() {
        uint8_t macBytes[6];
        if (!parseMAC(newMAC, macBytes)) return false;
        
        // Show current
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
            char current[18];
            macToStr((uint8_t*)ifr.ifr_hwaddr.sa_data, current);
            std::cout << "[*] Current MAC: " << current << "\n";
        }
        
        // Kill interfering processes
        system("killall wpa_supplicant 2>/dev/null");
        system("killall NetworkManager 2>/dev/null");
        sleep(1);
        
        // Bring interface down
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        ioctl(sock, SIOCGIFFLAGS, &ifr);
        ifr.ifr_flags &= ~IFF_UP;
        ioctl(sock, SIOCSIFFLAGS, &ifr);
        usleep(200000);
        
        // Change MAC
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        memcpy(ifr.ifr_hwaddr.sa_data, macBytes, 6);
        
        if (ioctl(sock, SIOCSIFHWADDR, &ifr) < 0) {
            perror("[!] SIOCSIFHWADDR failed");
            return false;
        }
        
        // Bring back up
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        ioctl(sock, SIOCGIFFLAGS, &ifr);
        ifr.ifr_flags |= IFF_UP;
        ioctl(sock, SIOCSIFFLAGS, &ifr);
        
        std::cout << "[+] New MAC: " << newMAC << "\n";
        std::cout << "[*] Restart wpa_supplicant or NetworkManager\n";
        return true;
    }
    
    ~WiFiMACSpoof() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <wifi_interface> <new_mac>\n";
        return 1;
    }
    WiFiMACSpoof spoof(argv[1], argv[2]);
    return spoof.setMAC() ? 0 : 1;
}
