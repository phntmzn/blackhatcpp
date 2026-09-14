// Compile: g++ -o smtp_enum smtp_enum.cpp
// Run: ./smtp_enum <mail_server> <username_file>
// No special privileges required

#include <iostream>
#include <fstream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <string>
#include <vector>

class SMTPEnumerator {
private:
    int sock;
    std::string server;
    int port;
    
public:
    SMTPEnumerator(const std::string& s, int p = 25) : server(s), port(p) {}
    
    bool connect() {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return false;
        
        struct hostent* host = gethostbyname(server.c_str());
        if (!host) return false;
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        memcpy(&addr.sin_addr.s_addr, host->h_addr, host->h_length);
        
        if (::connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
            return false;
        }
        
        char buffer[1024];
        recv(sock, buffer, sizeof(buffer), 0);
        return true;
    }
    
    std::string sendCmd(const std::string& cmd) {
        std::string command = cmd + "\r\n";
        send(sock, command.c_str(), command.length(), 0);
        
        char buffer[1024];
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            return std::string(buffer);
        }
        return "";
    }
    
    void enumerate(const std::vector<std::string>& usernames) {
        sendCmd("EHLO test");
        
        for (const auto& user : usernames) {
            std::string response = sendCmd("VRFY " + user);
            if (response.find("250") != std::string::npos ||
                response.find("252") != std::string::npos) {
                std::cout << "[+] Valid user: " << user << std::endl;
            }
        }
    }
    
    ~SMTPEnumerator() { if (sock >= 0) close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <mail_server> <username_file>\n";
        return 1;
    }
    
    std::vector<std::string> usernames;
    std::ifstream file(argv[2]);
    std::string line;
    while (std::getline(file, line)) {
        usernames.push_back(line);
    }
    
    SMTPEnumerator enumerator(argv[1]);
    if (enumerator.connect()) {
        enumerator.enumerate(usernames);
    }
    return 0;
}