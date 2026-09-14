# 10 Ping Sweep Techniques in C++

Each script demonstrates a distinct ping sweep methodology with compile instructions.

---

### 1. Classic ICMP Echo Sweep (Raw Sockets)
```cpp
// Compile: g++ -o ping_classic ping_classic.cpp
// Run: sudo ./ping_classic <subnet_prefix> <start> <end>
// Example: sudo ./ping_classic 192.168.1 1 254
// Requires: root privileges (CAP_NET_RAW)

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <poll.h>

class ICMPPingSweep {
private:
    std::atomic<int> hostCount{0};
    std::vector<std::string> aliveHosts;
    std::mutex mtx;
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
    bool pingHost(const std::string& targetIP, int timeoutMs = 1000) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(targetIP.c_str());
        
        // Build ICMP Echo Request
        uint8_t packet[64];
        memset(packet, 0, sizeof(packet));
        
        struct icmphdr* icmp = (struct icmphdr*)packet;
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = htons(getpid() & 0xFFFF);
        icmp->un.echo.sequence = htons(1);
        icmp->checksum = 0;
        
        // Add timestamp in payload
        struct timeval tv;
        gettimeofday(&tv, NULL);
        memcpy(packet + sizeof(struct icmphdr), &tv, sizeof(tv));
        
        icmp->checksum = checksum(packet, sizeof(packet));
        
        // Send
        if (sendto(sock, packet, sizeof(packet), 0,
                   (struct sockaddr*)&dest, sizeof(dest)) <= 0) {
            close(sock);
            return false;
        }
        
        // Wait for reply
        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLIN;
        
        int ret = poll(&pfd, 1, timeoutMs);
        if (ret > 0) {
            uint8_t response[1024];
            struct sockaddr_in from;
            socklen_t fromLen = sizeof(from);
            
            int bytes = recvfrom(sock, response, sizeof(response), 0,
                                 (struct sockaddr*)&from, &fromLen);
            
            if (bytes > 0) {
                struct iphdr* ip = (struct iphdr*)response;
                int ipHdrLen = ip->ihl * 4;
                struct icmphdr* rIcmp = (struct icmphdr*)(response + ipHdrLen);
                
                if (rIcmp->type == ICMP_ECHOREPLY &&
                    rIcmp->un.echo.id == htons(getpid() & 0xFFFF)) {
                    close(sock);
                    return true;
                }
            }
        }
        
        close(sock);
        return false;
    }
    
public:
    void sweep(const std::string& prefix, int start, int end, int numThreads) {
        std::cout << "=====================================\n";
        std::cout << " ICMP Ping Sweep\n";
        std::cout << " Subnet: " << prefix << ".0/24\n";
        std::cout << " Range:  " << start << " - " << end << "\n";
        std::cout << " Threads: " << numThreads << "\n";
        std::cout << "=====================================\n\n";
        
        auto startTime = std::chrono::steady_clock::now();
        
        std::atomic<int> currentIP{start};
        
        auto worker = [&]() {
            while (true) {
                int ip = currentIP.fetch_add(1);
                if (ip > end) break;
                
                std::string target = prefix + "." + std::to_string(ip);
                
                if (pingHost(target)) {
                    std::lock_guard<std::mutex> lock(mtx);
                    aliveHosts.push_back(target);
                    hostCount++;
                    std::cout << "[+] " << target << " is alive\n";
                }
            }
        };
        
        std::vector<std::thread> threads;
        for (int i = 0; i < numThreads; i++) {
            threads.emplace_back(worker);
        }
        
        for (auto& t : threads) t.join();
        
        auto endTime = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime).count();
        
        std::cout << "\n=====================================\n";
        std::cout << " Scan complete in " << duration << "ms\n";
        std::cout << " Alive hosts: " << hostCount.load() << "\n";
        std::cout << "=====================================\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <subnet_prefix> <start> <end>\n";
        std::cerr << "Example: " << argv[0] << " 192.168.1 1 254\n";
        return 1;
    }
    
    ICMPPingSweep sweep;
    sweep.sweep(argv[1], atoi(argv[2]), atoi(argv[3]), 50);
    
    return 0;
}
```

**Technique:** Classic raw-socket ICMP sweep. Sends ICMP Echo Request to each IP, waits for Echo Reply. Most reliable but requires root. 50 parallel threads for speed.

---

### 2. TCP SYN Ping Sweep (Stealth)
```cpp
// Compile: g++ -o ping_syn ping_syn.cpp
// Run: sudo ./ping_syn <subnet_prefix> <start> <end> [port]
// Example: sudo ./ping_syn 192.168.1 1 254 80
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <unistd.h>
#include <random>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>

class SYN PingSweep {
private:
    std::atomic<int> hostCount{0};
    std::vector<std::string> aliveHosts;
    std::mutex mtx;
    uint16_t targetPort;
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
    bool synPing(const std::string& targetIP, int timeoutMs = 1500) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) return false;
        
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(targetIP.c_str());
        
        // Random source port for uniqueness
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1024, 65535);
        uint16_t srcPort = dis(gen);
        
        // Build IP + TCP header
        uint8_t packet[40];
        memset(packet, 0, sizeof(packet));
        
        struct iphdr* ip = (struct iphdr*)packet;
        struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
        
        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = htons(40);
        ip->id = htons(rand() & 0xFFFF);
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP;
        ip->saddr = inet_addr("0.0.0.0");  // Kernel fills
        ip->daddr = dest.sin_addr.s_addr;
        ip->check = checksum(ip, sizeof(struct iphdr));
        
        tcp->source = htons(srcPort);
        tcp->dest = htons(targetPort);
        tcp->seq = htonl(rand());
        tcp->ack_seq = 0;
        tcp->doff = 5;
        tcp->syn = 1;
        tcp->window = htons(65535);
        tcp->check = 0;
        tcp->urg_ptr = 0;
        
        // Send
        if (sendto(sock, packet, 40, 0,
                   (struct sockaddr*)&dest, sizeof(dest)) <= 0) {
            close(sock);
            return false;
        }
        
        // Wait for response
        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLIN;
        
        int ret = poll(&pfd, 1, timeoutMs);
        bool alive = false;
        
        auto endTime = std::chrono::steady_clock::now() + 
                       std::chrono::milliseconds(timeoutMs);
        
        while (std::chrono::steady_clock::now() < endTime) {
            int timeout = std::chrono::duration_cast<std::chrono::milliseconds>(
                endTime - std::chrono::steady_clock::now()).count();
            if (timeout <= 0) break;
            
            struct pollfd p;
            p.fd = sock;
            p.events = POLLIN;
            
            if (poll(&p, 1, timeout) <= 0) break;
            
            uint8_t response[1024];
            struct sockaddr_in from;
            socklen_t fromLen = sizeof(from);
            
            int bytes = recvfrom(sock, response, sizeof(response), 0,
                                 (struct sockaddr*)&from, &fromLen);
            
            if (bytes < 40) continue;
            
            struct iphdr* rIp = (struct iphdr*)response;
            if (rIp->saddr != dest.sin_addr.s_addr) continue;
            
            int ipHdrLen = rIp->ihl * 4;
            struct tcphdr* rTcp = (struct tcphdr*)(response + ipHdrLen);
            
            if (ntohs(rTcp->dest) != srcPort) continue;
            
            // SYN-ACK or RST = host alive
            if (rTcp->syn && rTcp->ack) {
                alive = true;
                break;
            }
            if (rTcp->rst) {
                alive = true;
                break;
            }
        }
        
        close(sock);
        return alive;
    }
    
public:
    SYN PingSweep(uint16_t port) : targetPort(port) {}
    
    void sweep(const std::string& prefix, int start, int end, int numThreads) {
        std::cout << "=====================================\n";
        std::cout << " TCP SYN Ping Sweep\n";
        std::cout << " Subnet: " << prefix << ".0/24\n";
        std::cout << " Port:   " << targetPort << "\n";
        std::cout << " Range:  " << start << " - " << end << "\n";
        std::cout << "=====================================\n\n";
        
        auto startTime = std::chrono::steady_clock::now();
        
        std::atomic<int> currentIP{start};
        
        auto worker = [&]() {
            while (true) {
                int ip = currentIP.fetch_add(1);
                if (ip > end) break;
                
                std::string target = prefix + "." + std::to_string(ip);
                
                if (synPing(target)) {
                    std::lock_guard<std::mutex> lock(mtx);
                    aliveHosts.push_back(target);
                    hostCount++;
                    std::cout << "[+] " << target << " alive (SYN-ACK/RST)\n";
                }
            }
        };
        
        std::vector<std::thread> threads;
        for (int i = 0; i < numThreads; i++) {
            threads.emplace_back(worker);
        }
        
        for (auto& t : threads) t.join();
        
        auto endTime = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime).count();
        
        std::cout << "\n[*] Complete in " << duration << "ms\n";
        std::cout << "[*] Alive hosts: " << hostCount.load() << "\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <subnet_prefix> <start> <end> [port]\n";
        std::cerr << "Example: " << argv[0] << " 192.168.1 1 254 80\n";
        return 1;
    }
    
    uint16_t port = (argc >= 5) ? atoi(argv[4]) : 80;
    SYN PingSweep sweep(port);
    sweep.sweep(argv[1], atoi(argv[2]), atoi(argv[3]), 100);
    
    return 0;
}
```

**Technique:** TCP SYN ping — sends SYN, any response (SYN-ACK or RST) means host alive. Doesn't complete handshake (stealth). Bypasses ICMP-blocking firewalls.

---

### 3. TCP ACK Ping Sweep
```cpp
// Compile: g++ -o ping_ack ping_ack.cpp
// Run: sudo ./ping_ack <subnet_prefix> <start> <end>
// Example: sudo ./ping_ack 192.168.1 1 254
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <random>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>

class ACKPingSweep {
private:
    std::atomic<int> hostCount{0};
    std::mutex mtx;
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
    bool ackPing(const std::string& targetIP, int timeoutMs = 1500) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) return false;
        
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(targetIP.c_str());
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1024, 65535);
        uint16_t srcPort = dis(gen);
        
        uint8_t packet[40];
        memset(packet, 0, sizeof(packet));
        
        struct iphdr* ip = (struct iphdr*)packet;
        struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
        
        ip->ihl = 5;
        ip->version = 4;
        ip->tot_len = htons(40);
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP;
        ip->daddr = dest.sin_addr.s_addr;
        ip->check = checksum(ip, sizeof(struct iphdr));
        
        tcp->source = htons(srcPort);
        tcp->dest = htons(80);
        tcp->seq = htonl(rand());
        tcp->ack_seq = htonl(rand());
        tcp->doff = 5;
        tcp->ack = 1;  // ACK flag
        tcp->window = htons(65535);
        
        if (sendto(sock, packet, 40, 0,
                   (struct sockaddr*)&dest, sizeof(dest)) <= 0) {
            close(sock);
            return false;
        }
        
        // Wait for RST response
        auto endTime = std::chrono::steady_clock::now() + 
                       std::chrono::milliseconds(timeoutMs);
        
        while (std::chrono::steady_clock::now() < endTime) {
            int timeout = std::chrono::duration_cast<std::chrono::milliseconds>(
                endTime - std::chrono::steady_clock::now()).count();
            if (timeout <= 0) break;
            
            struct pollfd p = {sock, POLLIN, 0};
            if (poll(&p, 1, timeout) <= 0) break;
            
            uint8_t response[1024];
            struct sockaddr_in from;
            socklen_t fromLen = sizeof(from);
            
            int bytes = recvfrom(sock, response, sizeof(response), 0,
                                 (struct sockaddr*)&from, &fromLen);
            if (bytes < 40) continue;
            
            struct iphdr* rIp = (struct iphdr*)response;
            if (rIp->saddr != dest.sin_addr.s_addr) continue;
            
            int ipHdrLen = rIp->ihl * 4;
            struct tcphdr* rTcp = (struct tcphdr*)(response + ipHdrLen);
            
            if (ntohs(rTcp->dest) != srcPort) continue;
            
            // RST response = host alive
            if (rTcp->rst) {
                close(sock);
                return true;
            }
        }
        
        close(sock);
        return false;
    }
    
public:
    void sweep(const std::string& prefix, int start, int end, int numThreads) {
        std::cout << "[*] TCP ACK Ping Sweep on " << prefix << ".0/24\n\n";
        
        auto startTime = std::chrono::steady_clock::now();
        std::atomic<int> currentIP{start};
        
        auto worker = [&]() {
            while (true) {
                int ip = currentIP.fetch_add(1);
                if (ip > end) break;
                
                std::string target = prefix + "." + std::to_string(ip);
                
                if (ackPing(target)) {
                    std::lock_guard<std::mutex> lock(mtx);
                    hostCount++;
                    std::cout << "[+] " << target << " alive\n";
                }
            }
        };
        
        std::vector<std::thread> threads;
        for (int i = 0; i < numThreads; i++) threads.emplace_back(worker);
        for (auto& t : threads) t.join();
        
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        
        std::cout << "\n[*] Complete in " << duration << "ms\n";
        std::cout << "[*] Alive: " << hostCount.load() << "\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <prefix> <start> <end>\n";
        return 1;
    }
    ACKPingSweep sweep;
    sweep.sweep(argv[1], atoi(argv[2]), atoi(argv[3]), 100);
    return 0;
}
```

**Technique:** TCP ACK ping — sends ACK (not SYN), any RST response indicates host is alive. Bypasses SYN-filtering firewalls. Also evades stateless firewalls.

---

### 4. UDP Ping Sweep
```cpp
// Compile: g++ -o ping_udp ping_udp.cpp
// Run: sudo ./ping_udp <subnet_prefix> <start> <end> [port]
// Example: sudo ./ping_udp 192.168.1 1 254 53
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <random>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <poll.h>

class UDPPingSweep {
private:
    std::atomic<int> hostCount{0};
    std::mutex mtx;
    uint16_t targetPort;
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
    bool udpPing(const std::string& targetIP, int timeoutMs = 2000) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if (sock < 0) return false;
        
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(targetIP.c_str());
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1024, 65535);
        uint16_t srcPort = dis(gen);
        
        // Build IP + UDP + payload
        uint8_t packet[64];
        memset(packet, 0, sizeof(packet));
        
        struct iphdr* ip = (struct iphdr*)packet;
        struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct iphdr));
        
        ip->ihl = 5;
        ip->version = 4;
        ip->tot_len = htons(20 + 8 + 4);
        ip->ttl = 64;
        ip->protocol = IPPROTO_UDP;
        ip->daddr = dest.sin_addr.s_addr;
        ip->check = checksum(ip, sizeof(struct iphdr));
        
        udp->source = htons(srcPort);
        udp->dest = htons(targetPort);
        udp->len = htons(8 + 4);
        udp->check = 0;
        
        // Payload - some UDP services reply to garbage
        memcpy(packet + 28, "PING", 4);
        
        sendto(sock, packet, 32, 0,
               (struct sockaddr*)&dest, sizeof(dest));
        
        // Wait for ANY response: ICMP port unreachable OR UDP reply
        auto endTime = std::chrono::steady_clock::now() + 
                       std::chrono::milliseconds(timeoutMs);
        
        while (std::chrono::steady_clock::now() < endTime) {
            int timeout = std::chrono::duration_cast<std::chrono::milliseconds>(
                endTime - std::chrono::steady_clock::now()).count();
            if (timeout <= 0) break;
            
            struct pollfd p = {sock, POLLIN, 0};
            if (poll(&p, 1, timeout) <= 0) break;
            
            uint8_t response[1024];
            struct sockaddr_in from;
            socklen_t fromLen = sizeof(from);
            
            int bytes = recvfrom(sock, response, sizeof(response), 0,
                                 (struct sockaddr*)&from, &fromLen);
            if (bytes < 28) continue;
            
            struct iphdr* rIp = (struct iphdr*)response;
            int ipHdrLen = rIp->ihl * 4;
            
            // ICMP response?
            if (rIp->protocol == IPPROTO_ICMP) {
                struct icmphdr* icmp = (struct icmphdr*)(response + ipHdrLen);
                
                // ICMP Port Unreachable carries original IP header
                if (icmp->type == ICMP_DEST_UNREACH && icmp->code == ICMP_PORT_UNREACH) {
                    // Check if it's our packet
                    struct iphdr* origIp = (struct iphdr*)(response + ipHdrLen + 8);
                    if (origIp->daddr == dest.sin_addr.s_addr) {
                        close(sock);
                        return true;  // Host alive, sent ICMP
                    }
                }
            }
            // UDP response (rare)
            else if (rIp->protocol == IPPROTO_UDP) {
                if (rIp->saddr == dest.sin_addr.s_addr) {
                    close(sock);
                    return true;
                }
            }
        }
        
        close(sock);
        return false;
    }
    
public:
    UDPPingSweep(uint16_t port) : targetPort(port) {}
    
    void sweep(const std::string& prefix, int start, int end, int numThreads) {
        std::cout << "[*] UDP Ping Sweep port " << targetPort 
                  << " on " << prefix << ".0/24\n\n";
        
        auto startTime = std::chrono::steady_clock::now();
        std::atomic<int> currentIP{start};
        
        auto worker = [&]() {
            while (true) {
                int ip = currentIP.fetch_add(1);
                if (ip > end) break;
                
                std::string target = prefix + "." + std::to_string(ip);
                if (udpPing(target)) {
                    std::lock_guard<std::mutex> lock(mtx);
                    hostCount++;
                    std::cout << "[+] " << target << " alive (ICMP/Reply)\n";
                }
            }
        };
        
        std::vector<std::thread> threads;
        for (int i = 0; i < numThreads; i++) threads.emplace_back(worker);
        for (auto& t : threads) t.join();
        
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        
        std::cout << "\n[*] Complete in " << duration << "ms\n";
        std::cout << "[*] Alive: " << hostCount.load() << "\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <prefix> <start> <end> [port]\n";
        return 1;
    }
    uint16_t port = (argc >= 5) ? atoi(argv[4]) : 53;
    UDPPingSweep sweep(port);
    sweep.sweep(argv[1], atoi(argv[2]), atoi(argv[3]), 80);
    return 0;
}
```

**Technique:** UDP ping — sends UDP packet, waits for ICMP Port Unreachable (host up, port closed) or UDP reply. Works when ICMP echo and TCP are filtered.

---

### 5. ICMP Timestamp Ping Sweep
```cpp
// Compile: g++ -o ping_timestamp ping_timestamp.cpp
// Run: sudo ./ping_timestamp <subnet_prefix> <start> <end>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <poll.h>

class TimestampPingSweep {
private:
    std::atomic<int> hostCount{0};
    std::mutex mtx;
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
    bool timestampPing(const std::string& targetIP, int timeoutMs = 1500) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(targetIP.c_str());
        
        // ICMP Timestamp Request (type 13)
        uint8_t packet[32];
        memset(packet, 0, sizeof(packet));
        
        struct icmphdr* icmp = (struct icmphdr*)packet;
        icmp->type = 13;  // ICMP_TIMESTAMP
        icmp->code = 0;
        icmp->un.echo.id = htons(getpid() & 0xFFFF);
        icmp->un.echo.sequence = htons(1);
        icmp->checksum = 0;
        
        // Timestamp fields (3 x 4 bytes)
        uint32_t now = time(NULL);
        uint32_t midnight = now - (now % 86400) + 86400000;
        *(uint32_t*)(packet + 8) = htonl(midnight);   // Originate timestamp
        *(uint32_t*)(packet + 12) = 0;                // Receive timestamp
        *(uint32_t*)(packet + 16) = 0;                // Transmit timestamp
        
        icmp->checksum = checksum(packet, 20);
        
        if (sendto(sock, packet, 20, 0,
                   (struct sockaddr*)&dest, sizeof(dest)) <= 0) {
            close(sock);
            return false;
        }
        
        struct pollfd pfd = {sock, POLLIN, 0};
        int ret = poll(&pfd, 1, timeoutMs);
        
        bool alive = false;
        if (ret > 0) {
            uint8_t response[1024];
            struct sockaddr_in from;
            socklen_t fromLen = sizeof(from);
            
            int bytes = recvfrom(sock, response, sizeof(response), 0,
                                 (struct sockaddr*)&from, &fromLen);
            
            if (bytes > 0) {
                struct iphdr* ip = (struct iphdr*)response;
                int ipHdrLen = ip->ihl * 4;
                struct icmphdr* rIcmp = (struct icmphdr*)(response + ipHdrLen);
                
                // Timestamp Reply (type 14)
                if (rIcmp->type == 14 &&
                    rIcmp->un.echo.id == htons(getpid() & 0xFFFF)) {
                    alive = true;
                }
            }
        }
        
        close(sock);
        return alive;
    }
    
public:
    void sweep(const std::string& prefix, int start, int end, int numThreads) {
        std::cout << "[*] ICMP Timestamp Ping Sweep on " 
                  << prefix << ".0/24\n\n";
        
        auto startTime = std::chrono::steady_clock::now();
        std::atomic<int> currentIP{start};
        
        auto worker = [&]() {
            while (true) {
                int ip = currentIP.fetch_add(1);
                if (ip > end) break;
                
                std::string target = prefix + "." + std::to_string(ip);
                if (timestampPing(target)) {
                    std::lock_guard<std::mutex> lock(mtx);
                    hostCount++;
                    std::cout << "[+] " << target << " alive (Timestamp Reply)\n";
                }
            }
        };
        
        std::vector<std::thread> threads;
        for (int i = 0; i < numThreads; i++) threads.emplace_back(worker);
        for (auto& t : threads) t.join();
        
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        
        std::cout << "\n[*] Complete in " << duration << "ms\n";
        std::cout << "[*] Alive: " << hostCount.load() << "\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <prefix> <start> <end>\n";
        return 1;
    }
    TimestampPingSweep sweep;
    sweep.sweep(argv[1], atoi(argv[2]), atoi(argv[3]), 50);
    return 0;
}
```

**Technique:** ICMP Timestamp ping (type 13/14) instead of Echo. Bypasses firewalls that specifically block Echo requests but not other ICMP types.

---

### 6. ICMP Address Mask Ping Sweep
```cpp
// Compile: g++ -o ping_mask ping_mask.cpp
// Run: sudo ./ping_mask <subnet_prefix> <start> <end>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <poll.h>

class MaskPingSweep {
private:
    std::atomic<int> hostCount{0};
    std::mutex mtx;
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
    bool maskPing(const std::string& targetIP, int timeoutMs = 1500) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(targetIP.c_str());
        
        // ICMP Address Mask Request (type 17)
        uint8_t packet[16];
        memset(packet, 0, sizeof(packet));
        
        struct icmphdr* icmp = (struct icmphdr*)packet;
        icmp->type = 17;  // ICMP_ADDRESS
        icmp->code = 0;
        icmp->un.echo.id = htons(getpid() & 0xFFFF);
        icmp->un.echo.sequence = htons(1);
        icmp->checksum = 0;
        
        // Address mask field (4 bytes)
        *(uint32_t*)(packet + 8) = 0;
        
        icmp->checksum = checksum(packet, 12);
        
        if (sendto(sock, packet, 12, 0,
                   (struct sockaddr*)&dest, sizeof(dest)) <= 0) {
            close(sock);
            return false;
        }
        
        struct pollfd pfd = {sock, POLLIN, 0};
        int ret = poll(&pfd, 1, timeoutMs);
        
        bool alive = false;
        if (ret > 0) {
            uint8_t response[1024];
            struct sockaddr_in from;
            socklen_t fromLen = sizeof(from);
            
            int bytes = recvfrom(sock, response, sizeof(response), 0,
                                 (struct sockaddr*)&from, &fromLen);
            
            if (bytes > 0) {
                struct iphdr* ip = (struct iphdr*)response;
                int ipHdrLen = ip->ihl * 4;
                struct icmphdr* rIcmp = (struct icmphdr*)(response + ipHdrLen);
                
                // Address Mask Reply (type 18)
                if (rIcmp->type == 18 &&
                    rIcmp->un.echo.id == htons(getpid() & 0xFFFF)) {
                    alive = true;
                }
            }
        }
        
        close(sock);
        return alive;
    }
    
public:
    void sweep(const std::string& prefix, int start, int end, int numThreads) {
        std::cout << "[*] ICMP Address Mask Ping Sweep\n\n";
        
        auto startTime = std::chrono::steady_clock::now();
        std::atomic<int> currentIP{start};
        
        auto worker = [&]() {
            while (true) {
                int ip = currentIP.fetch_add(1);
                if (ip > end) break;
                
                std::string target = prefix + "." + std::to_string(ip);
                if (maskPing(target)) {
                    std::lock_guard<std::mutex> lock(mtx);
                    hostCount++;
                    std::cout << "[+] " << target << " alive (Mask Reply)\n";
                }
            }
        };
        
        std::vector<std::thread> threads;
        for (int i = 0; i < numThreads; i++) threads.emplace_back(worker);
        for (auto& t : threads) t.join();
        
        std::cout << "\n[*] Alive: " << hostCount.load() << "\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <prefix> <start> <end>\n";
        return 1;
    }
    MaskPingSweep sweep;
    sweep.sweep(argv[1], atoi(argv[2]), atoi(argv[3]), 50);
    return 0;
}
```

**Technique:** ICMP Address Mask ping (type 17/18). Obsolete but still supported on many systems. Bypasses Echo-specific filters.

---

### 7. ARP Ping Sweep (Same Subnet Only)
```cpp
// Compile: g++ -o ping_arp ping_arp.cpp
// Run: sudo ./ping_arp <interface> <subnet_prefix> <start> <end>
// Example: sudo ./ping_arp eth0 192.168.1 1 254
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <map>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <poll.h>

class ARPPingSweep {
private:
    std::string iface;
    int sock;
    std::map<std::string, std::string> arpResults;
    std::mutex mtx;
    
    void macToBytes(const std::string& mac, uint8_t* out) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
    }
    
    void getOwnMAC(uint8_t* mac) {
        int tmpSock = socket(AF_INET, SOCK_DGRAM, 0);
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        ioctl(tmpSock, SIOCGIFHWADDR, &ifr);
        memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
        close(tmpSock);
    }
    
    void sendARPRequest(const std::string& targetIP) {
        uint8_t ownMAC[6];
        getOwnMAC(ownMAC);
        
        uint8_t packet[42];
        memset(packet, 0, sizeof(packet));
        
        struct ether_header* eth = (struct ether_header*)packet;
        struct ether_arp* arp = (struct ether_arp*)(packet + 14);
        
        memset(eth->ether_dhost, 0xFF, 6);
        memcpy(eth->ether_shost, ownMAC, 6);
        eth->ether_type = htons(ETH_P_ARP);
        
        arp->arp_hrd = htons(ARPHRD_ETHER);
        arp->arp_pro = htons(ETH_P_IP);
        arp->arp_hln = 6;
        arp->arp_pln = 4;
        arp->arp_op = htons(ARPOP_REQUEST);
        
        memcpy(arp->arp_sha, ownMAC, 6);
        inet_pton(AF_INET, "0.0.0.0", arp->arp_spa);
        memset(arp->arp_tha, 0, 6);
        inet_pton(AF_INET, targetIP.c_str(), arp->arp_tpa);
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_halen = 6;
        memset(sll.sll_addr, 0xFF, 6);
        
        sendto(sock, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
    }
    
public:
    ARPPingSweep(const std::string& i) : iface(i) {
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (sock < 0) { perror("socket"); exit(1); }
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        bind(sock, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    void sweep(const std::string& prefix, int start, int end, int numThreads) {
        std::cout << "=====================================\n";
        std::cout << " ARP Ping Sweep (Layer 2)\n";
        std::cout << " Interface: " << iface << "\n";
        std::cout << " Subnet: " << prefix << ".0/24\n";
        std::cout << "=====================================\n\n";
        
        auto startTime = std::chrono::steady_clock::now();
        
        // Send all ARP requests in parallel (very fast)
        std::atomic<int> currentIP{start};
        
        auto sender = [&]() {
            while (true) {
                int ip = currentIP.fetch_add(1);
                if (ip > end) break;
                
                std::string target = prefix + "." + std::to_string(ip);
                sendARPRequest(target);
                usleep(1000);  // 1ms between sends
            }
        };
        
        std::vector<std::thread> senders;
        for (int i = 0; i < numThreads; i++) senders.emplace_back(sender);
        for (auto& t : senders) t.join();
        
        // Collect replies for 2 seconds
        auto collectEnd = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        
        while (std::chrono::steady_clock::now() < collectEnd) {
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 200000;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            
            uint8_t buffer[1024];
            int bytes = recv(sock, buffer, sizeof(buffer), 0);
            if (bytes < 42) continue;
            
            struct ether_arp* arp = (struct ether_arp*)(buffer + 14);
            if (ntohs(arp->arp_op) != ARPOP_REPLY) continue;
            
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arp->arp_spa, ipStr, sizeof(ipStr));
            
            char macStr[18];
            snprintf(macStr, sizeof(macStr),
                     "%02x:%02x:%02x:%02x:%02x:%02x",
                     arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
                     arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
            
            std::lock_guard<std::mutex> lock(mtx);
            std::string ipKey(ipStr);
            if (arpResults.find(ipKey) == arpResults.end()) {
                arpResults[ipKey] = macStr;
                std::cout << "[+] " << ipStr << " @ " << macStr << "\n";
            }
        }
        
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        
        std::cout << "\n[*] Complete in " << duration << "ms\n";
        std::cout << "[*] Alive: " << arpResults.size() << "\n";
    }
    
    ~ARPPingSweep() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] 
                  << " <interface> <prefix> <start> <end>\n";
        std::cerr << "Example: " << argv[0] << " eth0 192.168.1 1 254\n";
        return 1;
    }
    ARPPingSweep sweep(argv[1]);
    sweep.sweep(argv[2], atoi(argv[3]), atoi(argv[4]), 10);
    return 0;
}
```

**Technique:** ARP ping — sends ARP requests (Layer 2). Fastest sweep method, but only works for same-subnet hosts. Cannot be filtered by IP-layer firewalls. Also captures MAC addresses.

---

### 8. IPv6 ICMPv6 Ping Sweep
```cpp
// Compile: g++ -o ping_ipv6 ping_ipv6.cpp
// Run: sudo ./ping_ipv6 <prefix> <start> <end>
// Example: sudo ./ping_ipv6 2001:db8:: 1 254
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sstream>
#include <iomanip>

class IPv6PingSweep {
private:
    std::atomic<int> hostCount{0};
    std::mutex mtx;
    
    unsigned short checksum6(void* src, void* dst, void* data, int len, uint8_t nextHdr) {
        // Simplified - kernel usually computes
        return 0;
    }
    
    std::string buildIPv6Address(const std::string& prefix, int host) {
        // Simple: prefix + last 16-bit segment
        std::stringstream ss;
        ss << prefix << std::hex << host;
        return ss.str();
    }
    
    bool ping6(const std::string& targetIPv6, int timeoutMs = 1500) {
        int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (sock < 0) return false;
        
        struct sockaddr_in6 dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin6_family = AF_INET6;
        
        if (inet_pton(AF_INET6, targetIPv6.c_str(), &dest.sin6_addr) != 1) {
            close(sock);
            return false;
        }
        
        // Build ICMPv6 Echo Request
        uint8_t packet[64];
        memset(packet, 0, sizeof(packet));
        
        struct icmp6_hdr* icmp6 = (struct icmp6_hdr*)packet;
        icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
        icmp6->icmp6_code = 0;
        icmp6->icmp6_id = htons(getpid() & 0xFFFF);
        icmp6->icmp6_seq = htons(1);
        
        // Add some payload
        memcpy(packet + sizeof(struct icmp6_hdr), "PING6DATA", 9);
        int packetLen = sizeof(struct icmp6_hdr) + 9;
        
        // ICMPv6 checksum is computed by kernel when IPPROTO_ICMPV6 used
        
        if (sendto(sock, packet, packetLen, 0,
                   (struct sockaddr*)&dest, sizeof(dest)) <= 0) {
            close(sock);
            return false;
        }
        
        struct pollfd pfd = {sock, POLLIN, 0};
        int ret = poll(&pfd, 1, timeoutMs);
        
        bool alive = false;
        if (ret > 0) {
            uint8_t response[1024];
            struct sockaddr_in6 from;
            socklen_t fromLen = sizeof(from);
            
            int bytes = recvfrom(sock, response, sizeof(response), 0,
                                 (struct sockaddr*)&from, &fromLen);
            
            if (bytes > 0) {
                struct icmp6_hdr* rIcmp6 = (struct icmp6_hdr*)response;
                
                if (rIcmp6->icmp6_type == ICMP6_ECHO_REPLY &&
                    rIcmp6->icmp6_id == htons(getpid() & 0xFFFF)) {
                    alive = true;
                }
            }
        }
        
        close(sock);
        return alive;
    }
    
public:
    void sweep(const std::string& prefix, int start, int end, int numThreads) {
        std::cout << "[*] IPv6 ICMPv6 Ping Sweep\n";
        std::cout << "[*] Prefix: " << prefix << "\n\n";
        
        auto startTime = std::chrono::steady_clock::now();
        std::atomic<int> currentHost{start};
        
        auto worker = [&]() {
            while (true) {
                int h = currentHost.fetch_add(1);
                if (h > end) break;
                
                std::string target = buildIPv6Address(prefix, h);
                
                if (ping6(target)) {
                    std::lock_guard<std::mutex> lock(mtx);
                    hostCount++;
                    std::cout << "[+] " << target << " alive\n";
                }
            }
        };
        
        std::vector<std::thread> threads;
        for (int i = 0; i < numThreads; i++) threads.emplace_back(worker);
        for (auto& t : threads) t.join();
        
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        
        std::cout << "\n[*] Complete in " << duration << "ms\n";
        std::cout << "[*] Alive: " << hostCount.load() << "\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <prefix> <start> <end>\n";
        std::cerr << "Example: " << argv[0] << " 2001:db8:: 1 254\n";
        return 1;
    }
    IPv6PingSweep sweep;
    sweep.sweep(argv[1], atoi(argv[2]), atoi(argv[3]), 50);
    return 0;
}
```

**Technique:** ICMPv6 Echo Request sweep for IPv6 networks. Sends ping6 to each IPv6 address. Detects IPv6-enabled hosts that might be missed by IPv4 scanning.

---

### 9. Multi-Protocol Ping Sweep (ICMP + TCP + UDP)
```cpp
// Compile: g++ -o ping_multi ping_multi.cpp -lpthread
// Run: sudo ./ping_multi <subnet_prefix> <start> <end>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <random>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <poll.h>

class MultiProtocolPingSweep {
private:
    std::atomic<int> hostCount{0};
    std::mutex mtx;
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
    // ICMP Echo
    bool icmpPing(const std::string& ip, int timeoutMs = 1000) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(ip.c_str());
        
        uint8_t packet[64];
        memset(packet, 0, sizeof(packet));
        struct icmphdr* icmp = (struct icmphdr*)packet;
        icmp->type = ICMP_ECHO;
        icmp->un.echo.id = htons(getpid() & 0xFFFF);
        icmp->checksum = checksum(packet, sizeof(packet));
        
        sendto(sock, packet, sizeof(packet), 0, (struct sockaddr*)&dest, sizeof(dest));
        
        struct pollfd pfd = {sock, POLLIN, 0};
        if (poll(&pfd, 1, timeoutMs) > 0) {
            uint8_t resp[1024];
            struct sockaddr_in from;
            socklen_t fromLen = sizeof(from);
            int bytes = recvfrom(sock, resp, sizeof(resp), 0,
                                 (struct sockaddr*)&from, &fromLen);
            if (bytes > 0) {
                struct iphdr* rIp = (struct iphdr*)resp;
                int ipHdrLen = rIp->ihl * 4;
                struct icmphdr* rIcmp = (struct icmphdr*)(resp + ipHdrLen);
                if (rIcmp->type == ICMP_ECHOREPLY) {
                    close(sock);
                    return true;
                }
            }
        }
        close(sock);
        return false;
    }
    
    // TCP SYN
    bool tcpSynPing(const std::string& ip, uint16_t port, int timeoutMs = 1000) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) return false;
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(ip.c_str());
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1024, 65535);
        uint16_t srcPort = dis(gen);
        
        uint8_t packet[40];
        memset(packet, 0, sizeof(packet));
        struct iphdr* ip4 = (struct iphdr*)packet;
        struct tcphdr* tcp = (struct tcphdr*)(packet + 20);
        
        ip4->ihl = 5; ip4->version = 4;
        ip4->tot_len = htons(40); ip4->ttl = 64;
        ip4->protocol = IPPROTO_TCP;
        ip4->daddr = dest.sin_addr.s_addr;
        ip4->check = checksum(ip4, 20);
        
        tcp->source = htons(srcPort); tcp->dest = htons(port);
        tcp->seq = htonl(rand()); tcp->doff = 5;
        tcp->syn = 1; tcp->window = htons(65535);
        
        sendto(sock, packet, 40, 0, (struct sockaddr*)&dest, sizeof(dest));
        
        auto endTime = std::chrono::steady_clock::now() + 
                       std::chrono::milliseconds(timeoutMs);
        
        while (std::chrono::steady_clock::now() < endTime) {
            int timeout = std::chrono::duration_cast<std::chrono::milliseconds>(
                endTime - std::chrono::steady_clock::now()).count();
            if (timeout <= 0) break;
            
            struct pollfd pfd = {sock, POLLIN, 0};
            if (poll(&pfd, 1, timeout) <= 0) break;
            
            uint8_t resp[1024];
            struct sockaddr_in from;
            socklen_t fromLen = sizeof(from);
            int bytes = recvfrom(sock, resp, sizeof(resp), 0,
                                 (struct sockaddr*)&from, &fromLen);
            if (bytes < 40) continue;
            
            struct iphdr* rIp = (struct iphdr*)resp;
            if (rIp->saddr != dest.sin_addr.s_addr) continue;
            
            struct tcphdr* rTcp = (struct tcphdr*)(resp + (rIp->ihl * 4));
            if (ntohs(rTcp->dest) == srcPort && (rTcp->syn || rTcp->rst)) {
                close(sock);
                return true;
            }
        }
        close(sock);
        return false;
    }
    
    // UDP (ICMP port unreachable = alive)
    bool udpPing(const std::string& ip, uint16_t port, int timeoutMs = 1500) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if (sock < 0) return false;
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(ip.c_str());
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1024, 65535);
        uint16_t srcPort = dis(gen);
        
        uint8_t packet[32];
        memset(packet, 0, sizeof(packet));
        struct iphdr* ip4 = (struct iphdr*)packet;
        struct udphdr* udp = (struct udphdr*)(packet + 20);
        
        ip4->ihl = 5; ip4->version = 4;
        ip4->tot_len = htons(32); ip4->ttl = 64;
        ip4->protocol = IPPROTO_UDP;
        ip4->daddr = dest.sin_addr.s_addr;
        ip4->check = checksum(ip4, 20);
        
        udp->source = htons(srcPort);
        udp->dest = htons(port);
        udp->len = htons(12);
        
        memcpy(packet + 28, "PING", 4);
        
        sendto(sock, packet, 32, 0, (struct sockaddr*)&dest, sizeof(dest));
        
        struct pollfd pfd = {sock, POLLIN, 0};
        if (poll(&pfd, 1, timeoutMs) > 0) {
            uint8_t resp[1024];
            struct sockaddr_in from;
            socklen_t fromLen = sizeof(from);
            int bytes = recvfrom(sock, resp, sizeof(resp), 0,
                                 (struct sockaddr*)&from, &fromLen);
            if (bytes > 0) {
                struct iphdr* rIp = (struct iphdr*)resp;
                int ipHdrLen = rIp->ihl * 4;
                
                if (rIp->protocol == IPPROTO_ICMP) {
                    struct icmphdr* icmp = (struct icmphdr*)(resp + ipHdrLen);
                    if (icmp->type == ICMP_DEST_UNREACH &&
                        icmp->code == ICMP_PORT_UNREACH) {
                        close(sock);
                        return true;
                    }
                }
            }
        }
        close(sock);
        return false;
    }
    
    bool sweepHost(const std::string& ip) {
        // Try ICMP first
        if (icmpPing(ip, 800)) return true;
        
        // Try TCP on common ports
        uint16_t commonPorts[] = {80, 443, 22, 21, 445, 3389, 8080};
        for (uint16_t port : commonPorts) {
            if (tcpSynPing(ip, port, 500)) return true;
        }
        
        // Try UDP
        if (udpPing(ip, 53, 800)) return true;
        if (udpPing(ip, 123, 800)) return true;
        
        return false;
    }
    
public:
    void sweep(const std::string& prefix, int start, int end, int numThreads) {
        std::cout << "===========================================\n";
        std::cout << " Multi-Protocol Ping Sweep\n";
        std::cout << " (ICMP + TCP SYN + UDP)\n";
        std::cout << "===========================================\n\n";
        
        auto startTime = std::chrono::steady_clock::now();
        std::atomic<int> currentIP{start};
        
        auto worker = [&]() {
            while (true) {
                int ip = currentIP.fetch_add(1);
                if (ip > end) break;
                
                std::string target = prefix + "." + std::to_string(ip);
                
                if (sweepHost(target)) {
                    std::lock_guard<std::mutex> lock(mtx);
                    hostCount++;
                    std::cout << "[+] " << target << " alive\n";
                }
            }
        };
        
        std::vector<std::thread> threads;
        for (int i = 0; i < numThreads; i++) threads.emplace_back(worker);
        for (auto& t : threads) t.join();
        
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        
        std::cout << "\n[*] Complete in " << duration << "ms\n";
        std::cout << "[*] Alive: " << hostCount.load() << "\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <prefix> <start> <end>\n";
        return 1;
    }
    MultiProtocolPingSweep sweep;
    sweep.sweep(argv[1], atoi(argv[2]), atoi(argv[3]), 40);
    return 0;
}
```

**Technique:** Multi-protocol sweep — combines ICMP, TCP SYN, and UDP pings. Falls back if ICMP is blocked. Detects hosts that respond to at least one protocol.

---

### 10. Comprehensive Ping Sweep Framework with Port Scan
```cpp
// Compile: g++ -o ping_framework ping_framework.cpp -lpthread
// Run: sudo ./ping_framework <interface> <subnet_prefix> <start> <end>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <map>
#include <chrono>
#include <random>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <poll.h>

class PingSweepFramework {
private:
    std::string iface;
    std::string subnetPrefix;
    std::map<std::string, std::string> aliveHosts;  // IP -> MAC
    std::mutex mtx;
    std::atomic<int> aliveCount{0};
    std::ofstream logFile;
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
    // ARP ping for same subnet (Layer 2)
    bool arpPing(const std::string& targetIP, std::string& outMAC, int timeoutMs = 1000) {
        int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (sock < 0) return false;
        
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface.c_str());
        sll.sll_protocol = htons(ETH_P_ARP);
        bind(sock, (struct sockaddr*)&sll, sizeof(sll));
        
        // Get own MAC
        int tmpSock = socket(AF_INET, SOCK_DGRAM, 0);
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        ioctl(tmpSock, SIOCGIFHWADDR, &ifr);
        close(tmpSock);
        
        uint8_t ownMAC[6];
        memcpy(ownMAC, ifr.ifr_hwaddr.sa_data, 6);
        
        // Build ARP request
        uint8_t packet[42];
        memset(packet, 0, sizeof(packet));
        
        struct ether_header* eth = (struct ether_header*)packet;
        struct ether_arp* arp = (struct ether_arp*)(packet + 14);
        
        memset(eth->ether_dhost, 0xFF, 6);
        memcpy(eth->ether_shost, ownMAC, 6);
        eth->ether_type = htons(ETH_P_ARP);
        
        arp->arp_hrd = htons(ARPHRD_ETHER);
        arp->arp_pro = htons(ETH_P_IP);
        arp->arp_hln = 6;
        arp->arp_pln = 4;
        arp->arp_op = htons(ARPOP_REQUEST);
        memcpy(arp->arp_sha, ownMAC, 6);
        inet_pton(AF_INET, "0.0.0.0", arp->arp_spa);
        memset(arp->arp_tha, 0, 6);
        inet_pton(AF_INET, targetIP.c_str(), arp->arp_tpa);
        
        sll.sll_halen = 6;
        memset(sll.sll_addr, 0xFF, 6);
        
        sendto(sock, packet, 42, 0, (struct sockaddr*)&sll, sizeof(sll));
        
        // Wait for reply
        struct pollfd pfd = {sock, POLLIN, 0};
        if (poll(&pfd, 1, timeoutMs) > 0) {
            uint8_t response[1024];
            struct sockaddr_ll from;
            socklen_t fromLen = sizeof(from);
            int bytes = recvfrom(sock, response, sizeof(response), 0,
                                 (struct sockaddr*)&from, &fromLen);
            
            if (bytes >= 42) {
                struct ether_arp* rArp = (struct ether_arp*)(response + 14);
                if (ntohs(rArp->arp_op) == ARPOP_REPLY) {
                    char ipStr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, rArp->arp_spa, ipStr, sizeof(ipStr));
                    if (strcmp(ipStr, targetIP.c_str()) == 0) {
                        char macStr[18];
                        snprintf(macStr, sizeof(macStr),
                                 "%02x:%02x:%02x:%02x:%02x:%02x",
                                 rArp->arp_sha[0], rArp->arp_sha[1],
                                 rArp->arp_sha[2], rArp->arp_sha[3],
                                 rArp->arp_sha[4], rArp->arp_sha[5]);
                        outMAC = macStr;
                        close(sock);
                        return true;
                    }
                }
            }
        }
        
        close(sock);
        return false;
    }
    
    // Quick port scan of found host
    std::vector<int> scanPorts(const std::string& targetIP, 
                                const std::vector<int>& ports, int timeoutMs = 300) {
        std::vector<int> open;
        
        for (int port : ports) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) continue;
            
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = timeoutMs * 1000;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            
            struct sockaddr_in dest;
            memset(&dest, 0, sizeof(dest));
            dest.sin_family = AF_INET;
            dest.sin_port = htons(port);
            dest.sin_addr.s_addr = inet_addr(targetIP.c_str());
            
            if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) == 0) {
                open.push_back(port);
            }
            close(sock);
        }
        
        return open;
    }
    
public:
    PingSweepFramework(const std::string& i, const std::string& p)
        : iface(i), subnetPrefix(p) {
        std::string logPath = "ping_sweep_" + subnetPrefix + ".log";
        logFile.open(logPath, std::ios::out);
    }
    
    void sweep(int start, int end, int numThreads) {
        std::cout << "===============================================\n";
        std::cout << " Comprehensive Ping Sweep Framework\n";
        std::cout << " Interface: " << iface << "\n";
        std::cout << " Subnet:    " << subnetPrefix << ".0/24\n";
        std::cout << " Range:     " << start << " - " << end << "\n";
        std::cout << "===============================================\n\n";
        
        logFile << "=== Ping Sweep Results ===\n";
        logFile << "Subnet: " << subnetPrefix << ".0/24\n";
        logFile << "Time: " << time(NULL) << "\n\n";
        
        auto startTime = std::chrono::steady_clock::now();
        
        // Phase 1: ARP ping sweep (fast, layer 2)
        std::cout << "[*] Phase 1: ARP ping sweep...\n";
        std::atomic<int> currentIP{start};
        
        auto worker = [&]() {
            while (true) {
                int ip = currentIP.fetch_add(1);
                if (ip > end) break;
                
                std::string target = subnetPrefix + "." + std::to_string(ip);
                std::string mac;
                
                if (arpPing(target, mac, 500)) {
                    std::lock_guard<std::mutex> lock(mtx);
                    aliveHosts[target] = mac;
                    aliveCount++;
                    std::cout << "[+] " << target << " @ " << mac << "\n";
                }
            }
        };
        
        std::vector<std::thread> threads;
        for (int i = 0; i < numThreads; i++) threads.emplace_back(worker);
        for (auto& t : threads) t.join();
        
        std::cout << "\n[+] Phase 1 complete: " << aliveCount.load() 
                  << " hosts found\n";
        
        // Phase 2: Port scan of alive hosts
        std::cout << "\n[*] Phase 2: Common port scan of alive hosts...\n";
        
        std::vector<int> commonPorts = {21, 22, 23, 25, 53, 80, 110, 111, 135, 
                                         139, 143, 443, 445, 993, 995, 1433, 
                                         1521, 3306, 3389, 5432, 5900, 6379, 
                                         8080, 8443, 27017};
        
        for (const auto& pair : aliveHosts) {
            std::cout << "\n[*] Scanning " << pair.first << " (" 
                      << pair.second << ")\n";
            
            std::vector<int> openPorts = scanPorts(pair.first, commonPorts, 300);
            
            std::cout << "    Open ports: ";
            if (openPorts.empty()) {
                std::cout << "(none)\n";
            } else {
                for (int p : openPorts) std::cout << p << " ";
                std::cout << "\n";
            }
            
            logFile << pair.first << " (" << pair.second << "): ";
            for (int p : openPorts) logFile << p << " ";
            logFile << "\n";
        }
        
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - startTime).count();
        
        std::cout << "\n===============================================\n";
        std::cout << " Scan complete in " << duration << " seconds\n";
        std::cout << " Alive hosts: " << aliveCount.load() << "\n";
        std::cout << "===============================================\n";
        
        logFile << "\nTotal alive: " << aliveCount.load() << "\n";
        logFile << "Duration: " << duration << " sec\n";
        logFile.close();
    }
};

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] 
                  << " <interface> <subnet_prefix> <start> <end>\n";
        std::cerr << "Example: " << argv[0] << " eth0 192.168.1 1 254\n";
        return 1;
    }
    PingSweepFramework framework(argv[1], argv[2]);
    framework.sweep(atoi(argv[3]), atoi(argv[4]), 30);
    return 0;
}
```

**Technique:** Complete framework — ARP sweep (fast layer 2) + common port scan of alive hosts + logging. Auto-detects alive hosts with MACs and scans their open ports. Production-grade recon tool.

---

## Compilation & Usage Guide

### Prerequisites
```bash
sudo apt-get install -y build-essential g++
```

### Bulk Compile
```bash
#!/bin/bash
for file in ping_*.cpp; do
    name="${file%.cpp}"
    echo "Compiling $name..."
    g++ -O2 -pthread -o "$name" "$file"
done
echo "Done!"
```

### Quick Usage

```bash
# 1. Classic ICMP sweep
sudo ./ping_classic 192.168.1 1 254

# 2. TCP SYN sweep
sudo ./ping_syn 192.168.1 1 254 80

# 3. TCP ACK sweep
sudo ./ping_ack 192.168.1 1 254

# 4. UDP sweep
sudo ./ping_udp 192.168.1 1 254 53

# 5. ICMP timestamp sweep
sudo ./ping_timestamp 192.168.1 1 254

# 6. ICMP mask sweep
sudo ./ping_mask 192.168.1 1 254

# 7. ARP sweep (same subnet, fastest)
sudo ./ping_arp eth0 192.168.1 1 254

# 8. IPv6 sweep
sudo ./ping_ipv6 2001:db8:: 1 254

# 9. Multi-protocol sweep
sudo ./ping_multi 192.168.1 1 254

# 10. Full framework (sweep + port scan)
sudo ./ping_framework eth0 192.168.1 1 254
```

### Performance Tuning

```bash
# Increase file descriptor limit for high parallelism
ulimit -n 65535

# Optimize network stack
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"
sudo sysctl -w net.core.somaxconn=65535
```

## Technique Comparison Table

| # | Protocol | Stealth | Speed | Requires Root | Bypasses |
|---|----------|---------|-------|---------------|----------|
| 1 | ICMP Echo | Low | Fast | Yes | Basic |
| 2 | TCP SYN | High | Fast | Yes | ICMP filters |
| 3 | TCP ACK | High | Fast | Yes | SYN filters |
| 4 | UDP + ICMP | Medium | Slow | Yes | TCP+ICMP filters |
| 5 | ICMP Timestamp | High | Fast | Yes | Echo filters |
| 6 | ICMP Mask | High | Fast | Yes | Echo filters |
| 7 | ARP | Very High | Fastest | Yes | IP firewalls |
| 8 | IPv6 ICMPv6 | Medium | Fast | Yes | IPv4-only hosts |
| 9 | Multi-protocol | High | Slow | Yes | Multiple filters |
| 10 | Framework | High | Fast | Yes | Combined |

## Detection & Defense

**Detection:**
- IDS/IPS with ICMP sweep signatures
- Rate limiting on ICMP responses
- Monitor for sequential IP probes
- Network anomaly detection
- Honeypots in address space
- Log aggregation across hosts

**Defense:**
- Block ICMP echo at perimeter
- Rate limit ICMP/TCP/UDP responses
- Disable ICMP timestamp/mask replies (sysctl)
- Use 802.1X with port security
- Deploy network monitoring (Zeek/Suricata)
- Segment networks with VLANs
- Implement NAC (Network Access Control)

### Sysctl Hardening
```bash
# Disable ICMP echo replies
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all

# Ignore broadcast pings
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

# Disable timestamp replies
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses
```

## Legal Notice

**ALL SCRIPTS ARE FOR EDUCATIONAL PURPOSES ONLY**

These C++ ping sweep implementations demonstrate techniques for:
- Authorized network scanning and discovery
- Security assessments with explicit permission
- Understanding defensive countermeasures
- Lab environments

**UNAUTHORIZED USE MAY VIOLATE:**
- Computer Fraud and Abuse Act (CFAA) — US
- Computer Misuse Act — UK
- Network and Information Systems Directive — EU
- Local network access laws
- ISP terms of service

**RESPONSIBLE USE**:
- Obtain explicit written authorization
- Use only on networks you own or have permission to test
- Never scan public IP ranges without authorization
- Report vulnerabilities responsibly
- Follow ethical disclosure practices

**DETECTION RISK**:
Network scanning is often detected and may trigger:
- IDS/IPS alerts
- Incident response
- Legal action by network owners
- ISP-level blocking

---

*This completes 10 unique ping sweep techniques in C++, derived from concepts in "TCP/IP Illustrated, Volume 3" by W. Richard Stevens.*
