// Compile: g++ -o mac_nmcli mac_nmcli.cpp
// Run: sudo ./mac_nmcli <connection_name> <new_mac>
// Requires: NetworkManager, root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <unistd.h>

class NMCliMACSpoof {
private:
    std::string connName, newMAC;
    
public:
    NMCliMACSpoof(const std::string& c, const std::string& mac)
        : connName(c), newMAC(mac) {}
    
    bool setMAC() {
        if (system("which nmcli > /dev/null 2>&1") != 0) {
            std::cerr << "[!] nmcli not found. Install NetworkManager.\n";
            return false;
        }
        
        std::cout << "[*] Modifying connection: " << connName << "\n";
        
        // Modify cloned MAC address
        std::stringstream cmd;
        cmd << "nmcli connection modify \"" << connName 
            << "\" 802-3-ethernet.cloned-mac-address " << newMAC;
        
        std::cout << "[*] " << cmd.str() << "\n";
        if (system(cmd.str().c_str()) != 0) {
            std::cerr << "[!] Failed to modify connection\n";
            return false;
        }
        
        // Reactivate connection
        std::stringstream reactivate;
        reactivate << "nmcli connection down \"" << connName << "\"";
        system(reactivate.str().c_str());
        sleep(1);
        
        std::stringstream up;
        up << "nmcli connection up \"" << connName << "\"";
        if (system(up.str().c_str()) != 0) {
            std::cerr << "[!] Failed to reactivate\n";
            return false;
        }
        
        // Show connection details
        std::stringstream show;
        show << "nmcli connection show \"" << connName 
             << "\" | grep cloned-mac";
        system(show.str().c_str());
        
        std::cout << "[+] MAC set persistently via NetworkManager\n";
        return true;
    }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <connection_name> <new_mac>\n";
        std::cerr << "    List connections: nmcli connection show\n";
        return 1;
    }
    NMCliMACSpoof spoof(argv[1], argv[2]);
    return spoof.setMAC() ? 0 : 1;
}
