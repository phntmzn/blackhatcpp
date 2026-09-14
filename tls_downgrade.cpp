// ============================================================
// tls_downgrade.cpp — detect version downgrade in TLS handshakes
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o tls_downgrade tls_downgrade.cpp \
//          -I/opt/homebrew/include -L/opt/homebrew/lib \
//          -lPcap++ -lPacket++ -lCommon++ -lpcap
// Usage:   sudo ./tls_downgrade <iface>
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
        if (!pay || !tcp) return;
        const uint8_t* d = pay->getPayload();
        size_t n = pay->getPayloadLen();
        if (n < 5 || d[0] != 0x16) return; // TLS handshake
        uint16_t ver = (d[1] << 8) | d[2];
        if (ver < 0x0303)
            std::printf("[!] Downgrade: TLS version 0x%04x on port %u\n",
                        ver, tcp->getDstPort());
    }, nullptr);
    while (true) sleep(1);
    return 0;
}
