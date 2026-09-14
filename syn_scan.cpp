// ============================================================
// syn_scan.cpp — TCP SYN port scanner
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o syn_scan syn_scan.cpp \
//          -I/opt/homebrew/include -L/opt/homebrew/lib \
//          -lPcap++ -lPacket++ -lCommon++ -lpcap
// Usage:   sudo ./syn_scan <target_ip> <start_port> <end_port>
// ============================================================
#include "PcapLiveDeviceList.h"
#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "EthLayer.h"
#include "Packet.h"
#include <cstdio>
#include <cstdlib>
#include <set>
#include <mutex>

int main(int argc, char** argv) {
    if (argc < 4) return 1;
    auto* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceList()[0];
    if (!dev || !dev->open()) return 1;

    pcpp::IPv4Address target(argv[2]);
    int start = std::atoi(argv[2]), end = std::atoi(argv[3]);
    std::set<uint16_t> open;
    std::mutex mtx;

    dev->startCapture([](pcpp::RawPacket* raw, pcpp::PcapLiveDevice*, void* cookie) {
        auto* state = static_cast<std::pair<std::set<uint16_t>*, std::mutex*>*>(cookie);
        pcpp::Packet pkt(raw);
        auto* tcp = pkt.getLayerOfType<pcpp::TcpLayer>();
        if (!tcp) return;
        if (tcp->getTcpHeader()->synFlag && tcp->getTcpHeader()->ackFlag) {
            std::lock_guard<std::mutex> lk(*state->second);
            state->first->insert(tcp->getSrcPort());
        }
    }, &std::make_pair(&open, &mtx));

    for (int p = start; p <= end; p++) {
        pcpp::EthLayer eth(dev->getMacAddress(), pcpp::MacAddress("ff:ff:ff:ff:ff:ff"), PCPP_ETHERTYPE_IP);
        pcpp::IPv4Layer ip(pcpp::IPv4Address(dev->getIPv4Address()), target);
        pcpp::TcpLayer tcp(40000 + (p % 20000), p);
        tcp.getTcpHeader()->synFlag = 1;

        pcpp::Packet pkt(64);
        pkt.addLayer(&eth); pkt.addLayer(&ip); pkt.addLayer(&tcp);
        pkt.computeCalculateFields();
        dev->sendPacket(&pkt);
    }
    sleep(3);
    for (auto p : open) std::printf("[open] %u\n", p);
    return 0;
}
