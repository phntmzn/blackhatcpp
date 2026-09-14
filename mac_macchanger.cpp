// Compile: g++ -o mac_macchanger mac_macchanger.cpp
// Run: sudo ./mac_macchanger <interface> <mode>
// Modes: random, vendor, same, other, reset
// Requires: root privileges, macchanger installed

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <map>
#include <string>

class MacChangerWrapper {
private:
    std::string iface;
    std::map<std::string, std::string> modes;
    
    void initModes() {
        modes["random"] = "-r";          // Fully random
        modes["vendor"] = "-A";          // Random same vendor
        modes["same"] = "-s";            // Same vendor only
        modes["other"] = "-A";           // Any vendor
        modes["reset"] = "-p";           // Reset to original
        modes["bmc"] = "-b";             // Burned-in MAC
        modes["list"] = "-l";            // List known vendors
    }
    
public:
    MacChangerWrapper(const std::string& i) : iface(i) {
        initModes();
        
        if (system("which macchanger > /dev/null 2>&1") != 0) {
            std::cerr << "[!] macchanger not installed\n";
            std::cerr << "    Install: sudo apt-get install macchanger\n";
            exit(1);
        }
    }
    
    bool changeMAC(const std::string& mode) {
        auto it = modes.find(mode);
        if (it == modes.end()) {
            std::cerr << "[!] Unknown mode: " << mode << "\n";
            std::cerr << "    Available: random, vendor, same, other, reset, bmc, list\n";
            return false;
        }
        
        // Bring interface down
        std::string cmd1 = "ip link set " + iface + " down";
        system(cmd1.c_str());
        usleep(100000);
        
        // Change with macchanger
        std::string cmd2 = "macchanger " + it->second + " " + iface;
        std::cout << "[*] " << cmd2 << "\n";
        int ret = system(cmd2.c_str());
        
        // Bring up
        std::string cmd3 = "ip link set " + iface + " up";
        system(cmd3.c_str());
        
        return ret == 0;
    }
    
    void showInfo() {
        std::string cmd = "macchanger -s " + iface;
        system(cmd.c_str());
    }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <mode>\n";
        std::cerr << "Modes: random, vendor, same, other, reset, bmc, list\n";
        return 1;
    }
    MacChangerWrapper changer(argv[1]);
    changer.changeMAC(argv[2]);
    changer.showInfo();
    return 0;
}
