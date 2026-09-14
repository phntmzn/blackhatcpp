// ============================================================
// kext_fuzz.cpp — userspace fuzzing harness for IOKit
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o kext_fuzz kext_fuzz.cpp -framework IOKit
// Usage:   ./kext_fuzz <service> <selector_start> <count>
// Note:    Based on KextFuzz (USENIX Security '23) methodology.
// ============================================================
#include <IOKit/IOKitLib.h>
#include <cstdio>
#include <cstdlib>
#include <array>
#include <random>

int main(int argc, char** argv) {
    if (argc < 4) {
        std::printf("usage: %s <service> <sel_start> <count>\n", argv[0]);
        return 1;
    }

    const char* svcname = argv[1];
    uint32_t start = static_cast<uint32_t>(std::atoi(argv[2]));
    uint32_t count = static_cast<uint32_t>(std::atoi(argv[3]));

    io_service_t svc = IOServiceGetMatchingService(
        kIOMasterPortDefault, IOServiceMatching(svcname));
    if (!svc) {
        std::printf("[-] no service\n");
        return 1;
    }

    io_connect_t conn;
    if (IOServiceOpen(svc, mach_task_self(), 0, &conn) != KERN_SUCCESS)
        return 1;

    std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<int> dist{0, 255};

    for (uint32_t i = 0; i < count; i++) {
        uint32_t sel = start + i;
        std::array<uint8_t, 512> in{};
        std::array<uint8_t, 512> out{};
        for (auto& b : in) b = static_cast<uint8_t>(dist(rng));
        size_t outSz = out.size();

        kern_return_t kr = IOConnectCallStructMethod(
            conn, sel, in.data(), in.size(), out.data(), &outSz);
        std::printf("sel 0x%x -> 0x%x\n", sel, kr);
    }

    IOServiceClose(conn);
    return 0;
}
