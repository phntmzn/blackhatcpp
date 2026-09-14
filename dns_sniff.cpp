// ============================================================
// dns_sniff.cpp — capture and print DNS queries
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o dns_sniff dns_sniff.cpp \
//          -I/opt/homebrew/include -L/opt/homebrew/lib \
//          -lPcap++ -lPacket++ -lCommon++ -lpcap
// Usage:   sudo ./dns_sniff <iface>
// ============================================================
#include "PcapLiveDeviceList.h"
#include "DnsLayer.h"
#include "Packet.h"
#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    auto* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(argv[1]);
    if (!dev || !dev->open()) return 1;

    dev->startCapture([](pcpp::RawPacket* raw, pcpp::PcapLiveDevice*, void*) {
        pcpp::Packet pkt(raw);
        auto* dns = pkt.getLayerOfType<pcpp::DnsLayer>();
        if (!dns) return;
        for (auto* q = dns->getFirstQuery(); q; q = dns->getNextQuery(q))
            std::printf("[DNS] %s\n", q->getName().c_str());
    }, nullptr);
    while (true) sleep(1);
    return 0;
}
