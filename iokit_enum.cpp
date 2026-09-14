// ============================================================
// iokit_enum.cpp — list all IOKit services
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o iokit_enum iokit_enum.cpp \
//          -framework IOKit -framework CoreFoundation
// Usage:   ./iokit_enum
// ============================================================
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <cstdio>

int main() {
    io_iterator_t iter;
    IOServiceGetMatchingServices(kIOMasterPortDefault,
        IOServiceMatching("IOService"), &iter);

    io_service_t svc;
    while ((svc = IOIteratorNext(iter))) {
        io_name_t name;
        IORegistryEntryGetName(svc, name);
        std::printf("%s\n", name);
        IOObjectRelease(svc);
    }
    IOObjectRelease(iter);
    return 0;
}
