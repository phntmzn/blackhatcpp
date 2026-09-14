// Compile: g++ -o mac_ifconfig mac_ifconfig.cpp
// Run: sudo ./mac_ifconfig <interface> <new_mac>
// Requires: root privileges, net-tools installed

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>

class IfconfigMACSpoof {
private:
    std::string iface, newMAC;
    
public:
    IfconfigMACSpoof(const std::string& i, const std::string& mac)
        : iface(i), newMAC(mac) {}
    
    bool setMAC() {
        std::cout << "[*] Using ifconfig command (legacy)\n";
        
        // Step 1: Bring interface down
        std::string cmd1 = "ifconfig " + iface + " down";
        std::cout << "[*] " << cmd1 << "\n";
        if (system(cmd1.c_str()) != 0) {
            std::cerr << "[!] Failed to bring interface down\n";
            return false;
        }
        
        usleep(100000);
        
        // Step 2: Change MAC
        std::string cmd2 = "ifconfig " + iface + " hw ether " + newMAC;
        std::cout << "[*] " << cmd2 << "\n";
        if (system(cmd2.c_str()) != 0) {
            std::cerr << "[!] Failed to change MAC\n";
            return false;
        }
        
        // Step 3: Bring interface up
        std::string cmd3 = "ifconfig " + iface + " up";
        std::cout << "[*] " << cmd3 << "\n";
        if (system(cmd3.c_str()) != 0) {
            std::cerr << "[!] Failed to bring interface up\n";
            return false;
        }
        
        // Verify
        std::string verify = "ifconfig " + iface + " | grep -o 'HWaddr.*'";
        std::cout << "\n[*] Current: ";
        system(verify.c_str());
        
        return true;
    }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <new_mac>\n";
        return 1;
    }
    IfconfigMACSpoof spoof(argv[1], argv[2]);
    return spoof.setMAC() ? 0 : 1;
}
