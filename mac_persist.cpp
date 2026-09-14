// Compile: g++ -o mac_persist mac_persist.cpp
// Run: sudo ./mac_persist <interface> <new_mac>
// Requires: root privileges, systemd-networkd

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <unistd.h>

class PersistentMACSpoof {
private:
    std::string iface, newMAC;
    
public:
    PersistentMACSpoof(const std::string& i, const std::string& mac)
        : iface(i), newMAC(mac) {}
    
    bool applyNow() {
        // Change MAC immediately
        std::string cmd1 = "ip link set " + iface + " down";
        system(cmd1.c_str());
        usleep(100000);
        
        std::string cmd2 = "ip link set " + iface + " address " + newMAC;
        int ret = system(cmd2.c_str());
        
        std::string cmd3 = "ip link set " + iface + " up";
        system(cmd3.c_str());
        
        return ret == 0;
    }
    
    bool makePersistent() {
        // Create systemd-networkd .link file
        std::string linkFile = "/etc/systemd/network/10-" + iface + "-mac.link";
        
        std::ofstream out(linkFile);
        if (!out.is_open()) {
            std::cerr << "[!] Cannot write to " << linkFile << "\n";
            return false;
        }
        
        out << "[Match]\n";
        out << "OriginalName=" << iface << "\n";
        out << "\n";
        out << "[Link]\n";
        out << "MACAddressPolicy=none\n";
        out << "MACAddress=" << newMAC << "\n";
        out.close();
        
        std::cout << "[+] Created " << linkFile << "\n";
        
        // Reload systemd-networkd
        system("systemctl restart systemd-networkd 2>/dev/null");
        
        std::cout << "[+] MAC will persist across reboots\n";
        return true;
    }
    
    bool apply() {
        if (!applyNow()) {
            std::cerr << "[!] Failed to apply MAC now\n";
            return false;
        }
        return makePersistent();
    }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <new_mac>\n";
        return 1;
    }
    PersistentMACSpoof spoof(argv[1], argv[2]);
    return spoof.apply() ? 0 : 1;
}
