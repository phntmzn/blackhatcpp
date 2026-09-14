// ============================================================
// arp_monitor.cpp — detect duplicate ARP replies (spoof signal)
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o arp_monitor arp_monitor.cpp \
//          -I/opt/homebrew/include -L/opt/homebrew/lib \
//          -lPcap++ -lPacket++ -lCommon++ -lpcap
// Usage:   sudo ./arp_monitor <iface>
// ============================================================
#include "PcapLiveDeviceList.h"
#include "ArpLayer.h"
#include "Packet.h"
#include <unordered_map>
#include <string>
#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    auto* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(argv[1]);
    if (!dev || !dev->open()) return 1;

    std::unordered_map<std::string, std::string> seen;
    dev->startCapture([](pcpp::RawPacket* raw, pcpp::PcapLiveDevice*, void* cookie) {
        auto* seen = static_cast<std::unordered_map<std::string, std::string>*>(cookie);
        pcpp::Packet pkt(raw);
        auto* arp = pkt.getLayerOfType<pcpp::ArpLayer>();
        if (!arp) return;
        std::string ip = arp->getSenderIpAddr().toString();
        std::string mac = arp->getSenderMacAddress().toString();
        auto it = seen->find(ip);
        if (it != seen->end() && it->second != mac)
            std::printf("[!] ARP spoof: %s now at %s (was %s)\n",
                        ip.c_str(), mac.c_str(), it->second.c_str());
        (*seen)[ip] = mac;
    }, &seen);

    std::printf("[*] monitoring %s...\n", argv[1]);
    while (true) sleep(1);
    return 0;
}
