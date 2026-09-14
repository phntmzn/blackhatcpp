// Compile: g++ -o mac_random mac_random.cpp
// Run: sudo ./mac_random <interface>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <random>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_arp.h>

class RandomMACSpoof {
private:
    int sock;
    std::string iface;
    
    void generateRandomMAC(uint8_t* mac, bool locallyAdministered = true) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        for (int i = 0; i < 6; i++) {
            mac[i] = dis(gen);
        }
        
        // Set locally administered bit (bit 1 of first byte)
        if (locallyAdministered) {
            mac[0] |= 0x02;
        }
        
        // Ensure not multicast (bit 0 of first byte = 0)
        mac[0] &= ~0x01;
    }
    
    void macToStr(const uint8_t* mac, char* out) {
        snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    
public:
    RandomMACSpoof(const std::string& i) : iface(i) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) { perror("socket"); exit(1); }
    }
    
    bool setRandomMAC() {
        uint8_t macBytes[6];
        generateRandomMAC(macBytes);
        
        char macStr[18];
        macToStr(macBytes, macStr);
        
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        memcpy(ifr.ifr_hwaddr.sa_data, macBytes, 6);
        
        if (ioctl(sock, SIOCSIFHWADDR, &ifr) < 0) {
            perror("[!] SIOCSIFHWADDR failed");
            return false;
        }
        
        std::cout << "[+] Random MAC: " << macStr << "\n";
        return true;
    }
    
    ~RandomMACSpoof() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        return 1;
    }
    RandomMACSpoof spoof(argv[1]);
    return spoof.setRandomMAC() ? 0 : 1;
}
