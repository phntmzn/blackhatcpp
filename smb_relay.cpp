// Compile: g++ -o smb_relay smb_relay.cpp -lpthread
// Run: sudo ./smb_relay <listen_ip> <target_smb>
// Requires: root privileges, libpcap optional

#include <iostream>
#include <cstring>
#include <string>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

class SMBRelay {
private:
    int listenPort;
    std::string targetHost;
    
public:
    SMBRelay(const std::string& target) : listenPort(445), targetHost(target) {}
    
    void start() {
        int serverSock = socket(AF_INET, SOCK_STREAM, 0);
        int opt = 1;
        setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(listenPort);
        
        bind(serverSock, (struct sockaddr*)&addr, sizeof(addr));
        listen(serverSock, 10);
        
        std::cout << "SMB Relay listening on port " << listenPort << std::endl;
        
        while (true) {
            struct sockaddr_in clientAddr;
            socklen_t clientLen = sizeof(clientAddr);
            int clientSock = accept(serverSock, (struct sockaddr*)&clientAddr, &clientLen);
            
            // Connect to target
            int targetSock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in targetAddr;
            targetAddr.sin_family = AF_INET;
            targetAddr.sin_port = htons(445);
            targetAddr.sin_addr.s_addr = inet_addr(targetHost.c_str());
            
            if (::connect(targetSock, (struct sockaddr*)&targetAddr, sizeof(targetAddr)) != 0) {
                close(clientSock);
                continue;
            }
            
            std::thread([clientSock, targetSock]() {
                char buffer[4096];
                int bytes;
                // Relay client -> target
                while ((bytes = recv(clientSock, buffer, sizeof(buffer), 0)) > 0) {
                    send(targetSock, buffer, bytes, 0);
                }
                close(clientSock);
                close(targetSock);
            }).detach();
            
            std::thread([clientSock, targetSock]() {
                char buffer[4096];
                int bytes;
                // Relay target -> client
                while ((bytes = recv(targetSock, buffer, sizeof(buffer), 0)) > 0) {
                    send(clientSock, buffer, bytes, 0);
                }
                close(clientSock);
                close(targetSock);
            }).detach();
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) { std::cerr << "Usage: " << argv[0] << " <target_smb_ip>\n"; return 1; }
    SMBRelay relay(argv[1]);
    relay.start();
    return 0;
}