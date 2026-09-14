// Compile: g++ -o mac_rotate mac_rotate.cpp -lpthread
// Run: sudo ./mac_rotate <interface> <interval_sec>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <random>
#include <chrono>
#include <thread>
#include <atomic>
#include <csignal>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_arp.h>

class MACRotator {
private:
    int sock;
    std::string iface;
    int intervalSec;
    std::atomic<bool> running{true};
    
    void generateMAC(uint8_t* mac) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        for (int i = 0; i < 6; i++) mac[i] = dis(gen);
        
        // Locally administered, unicast
        mac[0] = (mac[0] & 0xFC) | 0x02;
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
    static MACRotator* instance;
    
    MACRotator(const std::string& i, int interval)
        : iface(i), intervalSec(interval) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) { perror("socket"); exit(1); }
    }
    
    static void signalHandler(int) {
        instance->running = false;
        std::cout << "\n[*] Stopping MAC rotation\n";
    }
    
    void run() {
        instance = this;
        signal(SIGINT, signalHandler);
        signal(SIGTERM, signalHandler);
        
        std::cout << "[*] MAC rotation every " << intervalSec << " seconds\n";
        std::cout << "[*] Ctrl+C to stop\n\n";
        
        while (running.load()) {
            uint8_t mac[6];
            generateMAC(mac);
            
            if (setMAC(mac)) {
                char macStr[18];
                snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
                         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                std::cout << "[+] Rotated to: " << macStr << "\n";
            }
            
            for (int i = 0; i < intervalSec * 10 && running.load(); i++) {
                usleep(100000);
            }
        }
    }
    
    ~MACRotator() { close(sock); }
};

MACRotator* MACRotator::instance = nullptr;

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <interval_sec>\n";
        return 1;
    }
    MACRotator rotator(argv[1], atoi(argv[2]));
    rotator.run();
    return 0;
}
