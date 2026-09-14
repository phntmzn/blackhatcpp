// ============================================================
// http_sniff.cpp — capture cleartext HTTP requests
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o http_sniff http_sniff.cpp \
//          -I/opt/homebrew/include -L/opt/homebrew/lib \
//          -lPcap++ -lPacket++ -lCommon++ -lpcap
// Usage:   sudo ./http_sniff <iface>
// ============================================================
#include "PcapLiveDeviceList.h"
#include "TcpLayer.h"
#include "PayloadLayer.h"
#include "Packet.h"
#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    auto* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(argv[1]);
    if (!dev || !dev->open()) return 1;

    dev->startCapture([](pcpp::RawPacket* raw, pcpp::PcapLiveDevice*, void*) {
        pcpp::Packet pkt(raw);
        auto* pay = pkt.getLayerOfType<pcpp::PayloadLayer>();
        auto* tcp = pkt.getLayerOfType<pcpp::TcpLayer>();
        if (!pay || !tcp || tcp->getDstPort() != 80) return;
        const char* d = (const char*)pay->getPayload();
        if (strncmp(d, "GET ", 4) == 0 || strncmp(d, "POST ", 5) == 0)
            std::printf("[HTTP] %.120s\n", d);
    }, nullptr);
    while (true) sleep(1);
    return 0;
}
