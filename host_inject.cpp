// ============================================================
// host_inject.cpp — probe Host header handling
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o host_inject host_inject.cpp
// Usage:   ./host_inject <host> <port> <spoofed_host>
// ============================================================
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <string>

int main(int argc, char** argv) {
    if (argc < 4) return 1;
    hostent* he = gethostbyname(argv[1]);
    if (!he) return 1;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(std::atoi(argv[2]));
    memcpy(&dst.sin_addr, he->h_addr, he->h_length);
    if (connect(s, (sockaddr*)&dst, sizeof(dst)) < 0) return 1;

    std::string req = "GET / HTTP/1.1\r\nHost: ";
    req += argv[3];
    req += "\r\nConnection: close\r\n\r\n";
    send(s, req.c_str(), req.size(), 0);

    char buf[4096];
    int n = recv(s, buf, sizeof(buf) - 1, 0);
    if (n > 0) { buf[n] = 0; std::printf("%s\n", buf); }
    return 0;
}
