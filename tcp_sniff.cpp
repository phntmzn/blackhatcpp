// ============================================================
// tcp_sniff.cpp — print TCP segments (seq/ack/flags)
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o tcp_sniff tcp_sniff.cpp \
//          -I/opt/homebrew/include -L/opt/homebrew/lib \
//          -lPcap++ -lPacket++ -lCommon++ -lpcap
// Usage:   sudo ./tcp_sniff <iface>
// ============================================================
#include "PcapLiveDeviceList.h"
#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "Packet.h"
#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    auto* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(argv[1]);
    if (!dev || !dev->open()) return 1;

    dev->startCapture([](pcpp::RawPacket* raw, pcpp::PcapLiveDevice*, void*) {
        pcpp::Packet pkt(raw);
        auto* ip = pkt.getLayerOfType<pcpp::IPv4Layer>();
        auto* tcp = pkt.getLayerOfType<pcpp::TcpLayer>();
        if (!ip || !tcp) return;
        std::printf("%s:%u -> %s:%u seq=%u ack=%u flags=%s\n",
            ip->getSrcIPv4Address().toString().c_str(), tcp->getSrcPort(),
            ip->getDstIPv4Address().toString().c_str(), tcp->getDstPort(),
            tcp->getTcpHeader()->sequenceNumber,
            tcp->getTcpHeader()->ackNumber,
            tcp->getTcpHeader()->synFlag ? "SYN" :
            tcp->getTcpHeader()->finFlag ? "FIN" :
            tcp->getTcpHeader()->rstFlag ? "RST" : "ACK");
    }, nullptr);
    while (true) sleep(1);
    return 0;
}
