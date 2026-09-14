// Compile: g++ -o mac_restore mac_restore.cpp
// Run: sudo ./mac_restore <interface> [save|restore|new <mac>]
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

class MACSaveRestore {
private:
    int sock;
    std::string iface;
    std::string saveFile;
    
    void macToStr(const uint8_t* mac, char* out) {
        snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    
    bool parseMAC(const std::string& mac, uint8_t* out) {
        return sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                      &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]) == 6;
    }
    
    bool getCurrentMAC(uint8_t* mac) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) return false;
        memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
        return true;
    }
    
    bool setMAC(const uint8_t* mac) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        memcpy(ifr.ifr_hwaddr.sa_data, mac, 6);
        return ioctl(sock, SIOCSIFHWADDR, &ifr) == 0;
    }
    
public:
    MACSaveRestore(const std::string& i) : iface(i) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) { perror("socket"); exit(1); }
        saveFile = "/tmp/.mac_backup_" + iface;
    }
    
    bool saveOriginal() {
        uint8_t mac[6];
        if (!getCurrentMAC(mac)) return false;
        
        std::ofstream out(saveFile);
        if (!out.is_open()) return false;
        
        char macStr[18];
        macToStr(mac, macStr);
        out << macStr << "\n";
        out.close();
        
        std::cout << "[+] Saved original MAC: " << macStr << "\n";
        std::cout << "[*] Backup file: " << saveFile << "\n";
        return true;
    }
    
    bool restoreOriginal() {
        std::ifstream in(saveFile);
        if (!in.is_open()) {
            std::cerr << "[!] No backup found: " << saveFile << "\n";
            return false;
        }
        
        std::string macStr;
        std::getline(in, macStr);
        in.close();
        
        uint8_t mac[6];
        if (!parseMAC(macStr, mac)) return false;
        
        if (!setMAC(mac)) {
            std::cerr << "[!] Restore failed\n";
            return false;
        }
        
        std::cout << "[+] Restored original MAC: " << macStr << "\n";
        return true;
    }
    
    bool setNewMAC(const std::string& newMAC) {
        // Save original first if not already saved
        std::ifstream check(saveFile);
        if (!check.is_open()) {
            saveOriginal();
        }
        check.close();
        
        uint8_t mac[6];
        if (!parseMAC(newMAC, mac)) return false;
        
        if (!setMAC(mac)) {
            std::cerr << "[!] Failed to set new MAC\n";
            return false;
        }
        
        std::cout << "[+] MAC set: " << newMAC << "\n";
        return true;
    }
    
    ~MACSaveRestore() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <save|restore|new> [mac]\n";
        return 1;
    }
    
    MACSaveRestore mac(argv[1]);
    std::string action = argv[2];
    
    if (action == "save") {
        return mac.saveOriginal() ? 0 : 1;
    } else if (action == "restore") {
        return mac.restoreOriginal() ? 0 : 1;
    } else if (action == "new" && argc == 4) {
        return mac.setNewMAC(argv[3]) ? 0 : 1;
    }
    
    std::cerr << "[!] Invalid arguments\n";
    return 1;
}
