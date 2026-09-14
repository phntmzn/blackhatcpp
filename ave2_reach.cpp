// ============================================================
// ave2_reach.cpp — AppleAVE2 UserClient configure path PoC
// ------------------------------------------------------------
// Compile: clang++ -arch arm64 -O0 -g -std=c++17 \
//          -o ave2_reach ave2_reach.cpp -framework IOKit -framework CoreFoundation
// Usage:   ./ave2_reach
// Note:    Reachability only; no live overflow.
// ============================================================
#include <IOKit/IOKitLib.h>
#include <cstdio>
#include <array>

int main() {
    io_service_t svc = IOServiceGetMatchingService(
        kIOMasterPortDefault, IOServiceMatching("AppleAVE2"));
    if (!svc) {
        std::printf("[-] AppleAVE2 not found\n");
        return 1;
    }

    io_connect_t conn;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 1, &conn);
    std::printf("open type=1: 0x%x\n", kr);
    if (kr != KERN_SUCCESS) return 1;

    std::array<char, 0x920> in{};
    std::array<char, 0x100> out{};
    size_t outSz = out.size();
    kr = IOConnectCallStructMethod(conn, 1, in.data(), in.size(), out.data(), &outSz);
    std::printf("sel1 (create): 0x%x\n", kr);

    IOServiceClose(conn);
    return 0;
}
