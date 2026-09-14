// Compile: g++ -o mac_framework mac_framework.cpp -lpthread
// Run: sudo ./mac_framework <interface> <new_mac>
// Requires: root privileges

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <functional>
#include <vector>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

class MACFramework {
private:
    std::string iface, newMAC;
    std::vector<std::pair<std::string, std::function<bool()>>> methods;
    
    bool parseMAC(const std::string& mac, uint8_t* out) {
        return sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                      &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]) == 6;
    }
    
    void macToStr(const uint8_t* mac, char* out) {
        snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    
    // Method 1: ioctl
    bool methodIoctl() {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;
        
        uint8_t mac[6];
        if (!parseMAC(newMAC, mac)) { close(sock); return false; }
        
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        memcpy(ifr.ifr_hwaddr.sa_data, mac, 6);
        
        int ret = ioctl(sock, SIOCSIFHWADDR, &ifr);
        close(sock);
        return ret == 0;
    }
    
    // Method 2: Netlink
    bool methodNetlink() {
        int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (sock < 0) return false;
        
        uint8_t mac[6];
        if (!parseMAC(newMAC, mac)) { close(sock); return false; }
        
        char buffer[4096];
        memset(buffer, 0, sizeof(buffer));
        
        struct nlmsghdr* nlh = (struct nlmsghdr*)buffer;
        struct ifinfomsg* ifi = (struct ifinfomsg*)NLMSG_DATA(nlh);
        struct rtattr* rta;
        
        nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
        nlh->nlmsg_type = RTM_NEWLINK;
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        nlh->nlmsg_seq = 1;
        nlh->nlmsg_pid = getpid();
        
        ifi->ifi_family = AF_UNSPEC;
        ifi->ifi_index = if_nametoindex(iface.c_str());
        
        rta = (struct rtattr*)((char*)NLMSG_DATA(nlh) + NLMSG_ALIGN(sizeof(struct ifinfomsg)));
        rta->rta_type = IFLA_ADDRESS;
        rta->rta_len = RTA_LENGTH(6);
        memcpy(RTA_DATA(rta), mac, 6);
        nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
        
        struct sockaddr_nl dest;
        memset(&dest, 0, sizeof(dest));
        dest.nl_family = AF_NETLINK;
        
        struct iovec iov = {nlh, nlh->nlmsg_len};
        struct msghdr msg = {&dest, sizeof(dest), &iov, 1, NULL, 0, 0};
        
        int ret = sendmsg(sock, &msg, 0);
        close(sock);
        return ret >= 0;
    }
    
    // Method 3: ip command
    bool methodIPCommand() {
        std::string cmd1 = "ip link set " + iface + " down 2>/dev/null";
        system(cmd1.c_str());
        usleep(100000);
        std::string cmd2 = "ip link set " + iface + " address " + newMAC + " 2>/dev/null";
        int ret = system(cmd2.c_str());
        std::string cmd3 = "ip link set " + iface + " up 2>/dev/null";
        system(cmd3.c_str());
        return ret == 0;
    }
    
    // Method 4: ifconfig
    bool methodIfconfig() {
        std::string cmd1 = "ifconfig " + iface + " down 2>/dev/null";
        system(cmd1.c_str());
        usleep(100000);
        std::string cmd2 = "ifconfig " + iface + " hw ether " + newMAC + " 2>/dev/null";
        int ret = system(cmd2.c_str());
        std::string cmd3 = "ifconfig " + iface + " up 2>/dev/null";
        system(cmd3.c_str());
        return ret == 0;
    }
    
    // Method 5: macchanger
    bool methodMacchanger() {
        if (system("which macchanger > /dev/null 2>&1") != 0) return false;
        std::string cmd1 = "ip link set " + iface + " down 2>/dev/null";
        system(cmd1.c_str());
        usleep(100000);
        std::string cmd2 = "macchanger --mac=" + newMAC + " " + iface + " 2>/dev/null";
        int ret = system(cmd2.c_str());
        std::string cmd3 = "ip link set " + iface + " up 2>/dev/null";
        system(cmd3.c_str());
        return ret == 0;
    }
    
    // Method 6: NetworkManager
    bool methodNMCLI() {
        if (system("which nmcli > /dev/null 2>&1") != 0) return false;
        
        // Find connection by iface
        std::string findConn = "nmcli -t -f NAME,DEVICE connection show | grep ':" 
                             + iface + "' | cut -d: -f1";
        FILE* fp = popen(findConn.c_str(), "r");
        if (!fp) return false;
        
        char connName[256] = {0};
        if (fgets(connName, sizeof(connName), fp) == nullptr) {
            pclose(fp);
            return false;
        }
        pclose(fp);
        
        // Trim newline
        size_t len = strlen(connName);
        if (len > 0 && connName[len-1] == '\n') connName[len-1] = '\0';
        
        if (strlen(connName) == 0) return false;
        
        std::string cmd = "nmcli connection modify \"" + std::string(connName)
                        + "\" 802-3-ethernet.cloned-mac-address " + newMAC
                        + " 2>/dev/null && nmcli connection up \""
                        + std::string(connName) + "\" 2>/dev/null";
        return system(cmd.c_str()) == 0;
    }
    
    bool verifyMAC() {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;
        
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
            close(sock);
            return false;
        }
        
        char current[18];
        macToStr((uint8_t*)ifr.ifr_hwaddr.sa_data, current);
        close(sock);
        
        return newMAC == current;
    }
    
public:
    MACFramework(const std::string& i, const std::string& mac)
        : iface(i), newMAC(mac) {
        
        // Register methods in priority order
        methods.push_back({"Netlink (modern)", [this]() { return methodNetlink(); }});
        methods.push_back({"ioctl (classic)", [this]() { return methodIoctl(); }});
        methods.push_back({"ip command", [this]() { return methodIPCommand(); }});
        methods.push_back({"macchanger", [this]() { return methodMacchanger(); }});
        methods.push_back({"NetworkManager", [this]() { return methodNMCLI(); }});
        methods.push_back({"ifconfig (legacy)", [this]() { return methodIfconfig(); }});
    }
    
    bool run() {
        std::cout << "===============================================\n";
        std::cout << " MAC Spoofing Framework\n";
        std::cout << " Interface: " << iface << "\n";
        std::cout << " New MAC:   " << newMAC << "\n";
        std::cout << "===============================================\n\n";
        
        // Validate MAC
        uint8_t mac[6];
        if (!parseMAC(newMAC, mac)) {
            std::cerr << "[!] Invalid MAC format\n";
            return false;
        }
        
        // Try each method
        for (auto& method : methods) {
            std::cout << "[*] Trying: " << method.first << "\n";
            
            if (method.second()) {
                usleep(500000);
                
                if (verifyMAC()) {
                    std::cout << "[+] SUCCESS: MAC changed via " << method.first << "\n";
                    return true;
                } else {
                    std::cout << "[-] Method returned OK but verification failed\n";
                }
            } else {
                std::cout << "[-] Method failed\n";
            }
            
            usleep(300000);
        }
        
        std::cerr << "\n[!] All methods failed\n";
        return false;
    }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <new_mac>\n";
        return 1;
    }
    MACFramework framework(argv[1], argv[2]);
    return framework.run() ? 0 : 1;
}
