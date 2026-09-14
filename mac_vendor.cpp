// Compile: g++ -o mac_vendor mac_vendor.cpp
// Run: sudo ./mac_vendor <interface> <vendor>
// Vendors: apple, cisco, intel, samsung, huawei, tp-link, netgear
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <random>
#include <map>
#include <vector>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_arp.h>

class VendorMACSpoof {
private:
    int sock;
    std::string iface;
    std::map<std::string, std::vector<std::vector<uint8_t>>> vendorOUIs;
    
    void initVendors() {
        // Common vendor OUIs (first 3 bytes)
        vendorOUIs["apple"] = {{0x00,0x1B,0x63}, {0x00,0x1E,0xC2}, {0x00,0x23,0xDF},
                               {0x00,0x25,0x00}, {0x00,0x26,0xBB}, {0x28,0xCF,0xE9}};
        vendorOUIs["cisco"] = {{0x00,0x00,0x0C}, {0x00,0x1A,0xA1}, {0x00,0x1B,0x0C},
                               {0x00,0x1B,0x53}, {0x00,0x1E,0x13}};
        vendorOUIs["intel"] = {{0x00,0x1B,0x21}, {0x00,0x1E,0x64}, {0x00,0x1E,0x67},
                               {0x00,0x21,0x5C}, {0x00,0x21,0x6A}};
        vendorOUIs["samsung"] = {{0x00,0x12,0xFB}, {0x00,0x15,0xB9}, {0x00,0x16,0x32},
                                 {0x00,0x1A,0x8A}, {0x00,0x1D,0x25}};
        vendorOUIs["huawei"] = {{0x00,0x18,0x82}, {0x00,0x1E,0x10}, {0x00,0x22,0xA1},
                                {0x00,0x25,0x9E}, {0x00,0x34,0xFE}};
        vendorOUIs["tp-link"] = {{0x00,0x14,0x78}, {0x00,0x19,0xE0}, {0x00,0x1D,0x0F},
                                 {0x00,0x21,0x27}, {0x00,0x23,0xCD}};
        vendorOUIs["netgear"] = {{0x00,0x09,0x5B}, {0x00,0x0F,0xB5}, {0x00,0x14,0x6C},
                                 {0x00,0x18,0x4D}, {0x00,0x1B,0x2F}};
    }
    
    void macToStr(const uint8_t* mac, char* out) {
        snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    
public:
    VendorMACSpoof(const std::string& i) : iface(i) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) { perror("socket"); exit(1); }
        initVendors();
    }
    
    bool setVendorMAC(const std::string& vendor) {
        auto it = vendorOUIs.find(vendor);
        if (it == vendorOUIs.end()) {
            std::cerr << "[!] Unknown vendor. Available: ";
            for (const auto& p : vendorOUIs) std::cerr << p.first << " ";
            std::cerr << "\n";
            return false;
        }
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> ouiDis(0, it->second.size() - 1);
        std::uniform_int_distribution<> byteDis(0, 255);
        
        const auto& oui = it->second[ouiDis(gen)];
        uint8_t mac[6] = {oui[0], oui[1], oui[2],
                         (uint8_t)byteDis(gen),
                         (uint8_t)byteDis(gen),
                         (uint8_t)byteDis(gen)};
        
        char macStr[18];
        macToStr(mac, macStr);
        
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        memcpy(ifr.ifr_hwaddr.sa_data, mac, 6);
        
        if (ioctl(sock, SIOCSIFHWADDR, &ifr) < 0) {
            perror("[!] SIOCSIFHWADDR failed");
            return false;
        }
        
        std::cout << "[+] " << vendor << " MAC: " << macStr << "\n";
        return true;
    }
    
    ~VendorMACSpoof() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <vendor>\n";
        return 1;
    }
    VendorMACSpoof spoof(argv[1]);
    return spoof.setVendorMAC(argv[2]) ? 0 : 1;
}
