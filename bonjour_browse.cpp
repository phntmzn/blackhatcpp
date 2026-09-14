// ============================================================
// bonjour_browse.cpp — browse _services._dns-sd._udp
// ------------------------------------------------------------
// Compile: clang++ -O2 -o bonjour_browse bonjour_browse.cpp -framework CoreServices -framework CoreFoundation
// Run:     ./bonjour_browse
// ============================================================
#include <dns_sd.h>
#include <cstdio>

void cb(DNSServiceRef, DNSServiceFlags, uint32_t, DNSServiceErrorType err,
        const char* name, const char* regtype, const char* domain, void*) {
    if (err == kDNSServiceErr_NoError)
        printf("service: %s.%s%s\n", name, regtype, domain);
}

int main() {
    DNSServiceRef ref;
    DNSServiceBrowse(&ref, 0, 0, "_services._dns-sd._udp", nullptr, cb, nullptr);
    DNSServiceProcessResult(ref);
    return 0;
}
