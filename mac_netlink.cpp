// Compile: g++ -o mac_netlink mac_netlink.cpp
// Run: sudo ./mac_netlink <interface> <new_mac>
// Requires: root privileges, Linux kernel 2.6.24+

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>

class NetlinkMACSpoof {
private:
    int sock;
    std::string iface, newMAC;
    
    bool parseMAC(const std::string& mac, uint8_t* out) {
        return sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                      &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]) == 6;
    }
    
public:
    NetlinkMACSpoof(const std::string& i, const std::string& mac)
        : iface(i), newMAC(mac) {
        sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (sock < 0) { perror("socket(AF_NETLINK)"); exit(1); }
    }
    
    bool setMAC() {
        uint8_t macBytes[6];
        if (!parseMAC(newMAC, macBytes)) {
            std::cerr << "[!] Invalid MAC\n";
            return false;
        }
        
        // Build netlink message
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
        
        // Add IFLA_ADDRESS attribute
        rta = (struct rtattr*)((char*)NLMSG_DATA(nlh) + NLMSG_ALIGN(sizeof(struct ifinfomsg)));
        rta->rta_type = IFLA_ADDRESS;
        rta->rta_len = RTA_LENGTH(6);
        memcpy(RTA_DATA(rta), macBytes, 6);
        
        nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
        
        // Send message
        struct sockaddr_nl dest;
        memset(&dest, 0, sizeof(dest));
        dest.nl_family = AF_NETLINK;
        
        struct iovec iov = {nlh, nlh->nlmsg_len};
        struct msghdr msg = {&dest, sizeof(dest), &iov, 1, NULL, 0, 0};
        
        if (sendmsg(sock, &msg, 0) < 0) {
            perror("[!] sendmsg");
            return false;
        }
        
        // Read ACK
        memset(buffer, 0, sizeof(buffer));
        int len = recv(sock, buffer, sizeof(buffer), 0);
        if (len < 0) {
            perror("[!] recv");
            return false;
        }
        
        struct nlmsghdr* ack = (struct nlmsghdr*)buffer;
        if (ack->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr* err = (struct nlmsgerr*)NLMSG_DATA(ack);
            if (err->error != 0) {
                std::cerr << "[!] Netlink error: " << strerror(-err->error) << "\n";
                return false;
            }
        }
        
        std::cout << "[+] MAC changed via netlink: " << newMAC << "\n";
        return true;
    }
    
    ~NetlinkMACSpoof() { close(sock); }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <new_mac>\n";
        return 1;
    }
    NetlinkMACSpoof spoof(argv[1], argv[2]);
    return spoof.setMAC() ? 0 : 1;
}
