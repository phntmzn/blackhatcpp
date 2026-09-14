// ============================================================
// iokit_fuzz.cpp — fuzz IOKit user client selectors
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o iokit_fuzz iokit_fuzz.cpp -framework IOKit
// Usage:   ./iokit_fuzz <service_name>
// ============================================================
#include <IOKit/IOKitLib.h>
#include <cstdio>
#include <array>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: %s <service>\n", argv[0]);
        return 1;
    }

    io_service_t svc = IOServiceGetMatchingService(
        kIOMasterPortDefault, IOServiceMatching(argv[1]));
    if (!svc) {
        std::printf("[-] service not found\n");
        return 1;
    }

    io_connect_t conn;
    if (IOServiceOpen(svc, mach_task_self(), 0, &conn) != KERN_SUCCESS) {
        std::printf("[-] open failed\n");
        return 1;
    }

    std::array<char, 256> in{};
    std::array<char, 256> out{};
    size_t outSz = out.size();

    for (uint32_t sel = 0; sel < 32; sel++) {
        outSz = out.size();
        kern_return_t kr = IOConnectCallStructMethod(
            conn, sel, in.data(), in.size(), out.data(), &outSz);
        std::printf("sel %u: 0x%x\n", sel, kr);
    }
    IOServiceClose(conn);
    return 0;
}
