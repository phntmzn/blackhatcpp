// ============================================================
// hpp_probe.cpp — duplicate parameter handling probe
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o hpp_probe hpp_probe.cpp
// Usage:   ./hpp_probe <host> <port> <path> <param>
// ============================================================
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <string>

int main(int argc, char** argv) {
    if (argc < 5) return 1;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(std::atoi(argv[2]));
    inet_pton(AF_INET, argv[1], &dst.sin_addr);
    if (connect(s, (sockaddr*)&dst, sizeof(dst)) < 0) return 1;

    std::string req = "GET ";
    req += argv[3];
    req += "?";
    req += argv[4]; req += "=A&";
    req += argv[4]; req += "=B&";
    req += argv[4]; req += "=C HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n";

    send(s, req.c_str(), req.size(), 0);
    char buf[4096];
    int n = recv(s, buf, sizeof(buf) - 1, 0);
    if (n > 0) { buf[n] = 0; std::printf("%s\n", buf); }
    return 0;
}
