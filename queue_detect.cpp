// Compile: g++ -o queue_detect queue_detect.cpp -lpthread
// Run: ./queue_detect <target_host> <port> <count>
// No special privileges required

#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <chrono>
#include <thread>

class QueueDetector {
private:
    std::string host;
    int port;
    
public:
    QueueDetector(const std::string& h, int p) : host(h), port(p) {}
    
    void detect(int count) {
        int successes = 0;
        
        for (int i = 0; i < count; i++) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) continue;
            
            struct hostent* server = gethostbyname(host.c_str());
            if (!server) { close(sock); continue; }
            
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            memcpy(&addr.sin_addr.s_addr, server->h_addr, server->h_length);
            
            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            
            if (::connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                successes++;
            }
            
            close(sock);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        double rate = (double)successes / count;
        std::cout << "Success rate: " << (rate * 100) << "%" << std::endl;
        
        if (rate < 0.5) {
            std::cout << "Queue likely full/overflowing" << std::endl;
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <host> <port> <count>\n";
        return 1;
    }
    QueueDetector detector(argv[1], atoi(argv[2]));
    detector.detect(atoi(argv[3]));
    return 0;
}