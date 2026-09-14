// ============================================================
// hdr_fuzz.cpp — fuzz HTTP headers for parser bugs
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o hdr_fuzz hdr_fuzz.cpp
// Usage:   ./hdr_fuzz <host> <port>
// ============================================================
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <random>
#include <vector>

int main(int argc, char** argv) {
    if (argc < 3) return 1;
    const char* headers[] = {
        "Content-Length: -1",
        "Content-Length: 99999999999999999999",
        "Transfer-Encoding: chunked\r\nContent-Length: 10",
        "X-Forwarded-For: 127.0.0.1\r\nX-Forwarded-For: 8.8.8.8",
        "Host: a\r\nHost: b",
        "Content-Length: 0x10",
        "Accept: \r\n\r\n\r\n",
        "Range: bytes=99999999999-",
    };

    for (auto* h : headers) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_port = htons(std::atoi(argv[2]));
        inet_pton(AF_INET, argv[1], &dst.sin_addr);
        if (connect(s, (sockaddr*)&dst, sizeof(dst)) < 0) continue;

        std::string req = "GET / HTTP/1.1\r\nHost: target\r\n";
        req += h;
        req += "\r\nConnection: close\r\n\r\n";
        send(s, req.c_str(), req.size(), 0);

        char buf[1024];
        int n = recv(s, buf, sizeof(buf) - 1, 0);
        if (n > 0) { buf[n] = 0; std::printf("[%s] -> %.60s\n", h, buf); }
        close(s);
    }
    return 0;
}
