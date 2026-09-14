// Compile: g++ -o mac_system mac_system.cpp
// Run: sudo ./mac_system <interface> <new_mac>
// Requires: root privileges, iproute2 installed

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>

class SystemMACSpoof {
private:
    std::string iface, newMAC;
    
public:
    SystemMACSpoof(const std::string& i, const std::string& mac)
        : iface(i), newMAC(mac) {}
    
    bool setMAC() {
        std::cout << "[*] Using system ip command\n";
        
        // Step 1: Bring interface down
        std::string cmd1 = "ip link set " + iface + " down";
        std::cout << "[*] " << cmd1 << "\n";
        if (system(cmd1.c_str()) != 0) {
            std::cerr << "[!] Failed to bring interface down\n";
            return false;
        }
        
        usleep(100000);
        
        // Step 2: Change MAC
        std::string cmd2 = "ip link set " + iface + " address " + newMAC;
        std::cout << "[*] " << cmd2 << "\n";
        if (system(cmd2.c_str()) != 0) {
            std::cerr << "[!] Failed to change MAC\n";
            std::string cmdUp = "ip link set " + iface + " up";
            system(cmdUp.c_str());
            return false;
        }
        
        // Step 3: Bring interface up
        std::string cmd3 = "ip link set " + iface + " up";
        std::cout << "[*] " << cmd3 << "\n";
        if (system(cmd3.c_str()) != 0) {
            std::cerr << "[!] Failed to bring interface up\n";
            return false;
        }
        
        // Verify
        std::string verify = "ip link show " + iface + " | grep ether";
        std::cout << "\n[*] Current MAC:\n";
        system(verify.c_str());
        
        return true;
    }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <new_mac>\n";
        return 1;
    }
    SystemMACSpoof spoof(argv[1], argv[2]);
    return spoof.setMAC() ? 0 : 1;
}
