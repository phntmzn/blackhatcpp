// Compile: g++ -o tcp_proxy tcp_proxy.cpp -lpthread
// Run: ./tcp_proxy <listen_port> <target_host> <target_port>
// No special privileges required

#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <thread>
#include <string>

class TCPProxy {
private:
    int listenPort;
    std::string targetHost;
    int targetPort;
    
    void forward(int src, int dst) {
        char buffer[4096];
        int bytes;
        while ((bytes = recv(src, buffer, sizeof(buffer), 0)) > 0) {
            send(dst, buffer, bytes, 0);
        }
        close(src);
        close(dst);
    }
    
public:
    TCPProxy(int lp, const std::string& th, int tp) 
        : listenPort(lp), targetHost(th), targetPort(tp) {}
    
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
        
        std::cout << "Proxy listening on port " << listenPort << std::endl;
        
        while (true) {
            struct sockaddr_in clientAddr;
            socklen_t clientLen = sizeof(clientAddr);
            int clientSock = accept(serverSock, (struct sockaddr*)&clientAddr, &clientLen);
            
            // Connect to target
            int targetSock = socket(AF_INET, SOCK_STREAM, 0);
            struct hostent* host = gethostbyname(targetHost.c_str());
            if (!host) { close(clientSock); continue; }
            
            struct sockaddr_in targetAddr;
            targetAddr.sin_family = AF_INET;
            targetAddr.sin_port = htons(targetPort);
            memcpy(&targetAddr.sin_addr.s_addr, host->h_addr, host->h_length);
            
            if (::connect(targetSock, (struct sockaddr*)&targetAddr, sizeof(targetAddr)) != 0) {
                close(clientSock);
                continue;
            }
            
            std::thread t1(&TCPProxy::forward, this, clientSock, targetSock);
            std::thread t2(&TCPProxy::forward, this, targetSock, clientSock);
            t1.detach();
            t2.detach();
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) { std::cerr << "Usage: " << argv[0] << " <listen_port> <host> <port>\n"; return 1; }
    TCPProxy proxy(atoi(argv[1]), argv[2], atoi(argv[3]));
    proxy.start();
    return 0;
}