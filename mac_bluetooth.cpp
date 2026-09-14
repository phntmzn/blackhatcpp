// Compile: g++ -o mac_bluetooth mac_bluetooth.cpp
// Run: sudo ./mac_bluetooth <hci_device> <new_mac>
// Requires: root privileges, BlueZ, hciconfig/bdaddr

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <string>
#include <unistd.h>

class BluetoothMACSpoof {
private:
    std::string hciDev, newMAC;
    
    // Convert MAC format "AA:BB:CC:DD:EE:FF" to "AABBCCDDEEFF"
    std::string stripColons(const std::string& mac) {
        std::string result;
        for (char c : mac) {
            if (c != ':') result += c;
        }
        return result;
    }
    
public:
    BluetoothMACSpoof(const std::string& dev, const std::string& mac)
        : hciDev(dev), newMAC(mac) {}
    
    bool setMAC() {
        std::cout << "[*] Bluetooth MAC spoof for " << hciDev << "\n";
        
        // Bring device down
        std::string down = "hciconfig " + hciDev + " down";
        std::cout << "[*] " << down << "\n";
        if (system(down.c_str()) != 0) {
            std::cerr << "[!] Failed to bring HCI down\n";
            return false;
        }
        sleep(1);
        
        // Try bdaddr tool first
        std::string bdaddrCmd = "bdaddr -i " + hciDev + " " + newMAC;
        std::cout << "[*] " << bdaddrCmd << "\n";
        
        if (system("which bdaddr > /dev/null 2>&1") == 0) {
            if (system(bdaddrCmd.c_str()) == 0) {
                std::cout << "[+] MAC changed via bdaddr\n";
            } else {
                std::cerr << "[!] bdaddr failed\n";
            }
        } else {
            // Fallback to hcitool
            std::string stripped = stripColons(newMAC);
            std::string hcitoolCmd = "hcitool -i " + hciDev + " cmd 0x3f 0x001 " + stripped;
            std::cout << "[*] Trying hcitool: " << hcitoolCmd << "\n";
            system(hcitoolCmd.c_str());
        }
        
        // Bring back up
        std::string up = "hciconfig " + hciDev + " up";
        std::cout << "[*] " << up << "\n";
        system(up.c_str());
        
        // Show result
        std::string show = "hciconfig " + hciDev;
        system(show.c_str());
        
        return true;
    }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <hci_device> <new_mac>\n";
        std::cerr << "Example: sudo " << argv[0] << " hci0 11:22:33:44:55:66\n";
        return 1;
    }
    BluetoothMACSpoof spoof(argv[1], argv[2]);
    return spoof.setMAC() ? 0 : 1;
}
