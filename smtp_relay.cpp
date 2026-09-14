// Compile: g++ -o smtp_relay smtp_relay.cpp
// Run: ./smtp_relay <mail_server> <test_email>
// No special privileges required

#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <string>

class SMTPRelayCheck {
private:
    int sock;
    std::string server;
    
public:
    SMTPRelayCheck(const std::string& s) : server(s) {}
    
    bool connect() {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return false;
        
        struct hostent* host = gethostbyname(server.c_str());
        if (!host) return false;
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(25);
        memcpy(&addr.sin_addr.s_addr, host->h_addr, host->h_length);
        
        return ::connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0;
    }
    
    std::string sendCmd(const std::string& cmd) {
        std::string command = cmd + "\r\n";
        send(sock, command.c_str(), command.length(), 0);
        char buffer[1024];
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) { buffer[bytes] = '\0'; return std::string(buffer); }
        return "";
    }
    
    bool checkRelay(const std::string& testEmail) {
        sendCmd("EHLO test");
        sendCmd("MAIL FROM:<relay-test@example.com>");
        std::string response = sendCmd("RCPT TO:<" + testEmail + ">");
        return response.find("250") != std::string::npos;
    }
    
    ~SMTPRelayCheck() { if (sock >= 0) close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) { std::cerr << "Usage: " << argv[0] << " <server> <email>\n"; return 1; }
    SMTPRelayCheck check(argv[1]);
    if (check.connect() && check.checkRelay(argv[2])) {
        std::cout << "[!] Open relay detected!\n";
    }
    return 0;
}