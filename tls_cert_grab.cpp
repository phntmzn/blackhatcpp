// ============================================================
// tls_cert_grab.cpp — fetch and print server certificate
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o tls_cert_grab tls_cert_grab.cpp \
//          -framework Security -framework CoreFoundation
// Usage:   ./tls_cert_grab <host> <port>
// ============================================================
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <nettle/ssl.h>  // Or use Network.framework / OpenSSL
#include <cstdio>
#include <cstdlib>

// NOTE: Apple's Security.framework doesn't expose a simple
// TLS-client API for raw cert grabbing. Use OpenSSL instead:
//   brew install openssl
//   clang++ -std=c++17 -O2 -o tls_cert_grab tls_cert_grab.cpp \
//     -I/opt/homebrew/opt/openssl/include \
//     -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h>

int main(int argc, char** argv) {
    if (argc < 3) { std::printf("usage: %s <host> <port>\n", argv[0]); return 1; }
    SSL_library_init();
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    BIO* bio = BIO_new_ssl_connect(ctx);
    BIO_set_conn_hostname(bio, (std::string(argv[1]) + ":" + argv[2]).c_str());

    SSL* ssl = nullptr;
    BIO_get_ssl(bio, &ssl);
    SSL_set_tlsext_host_name(ssl, argv[1]);

    if (BIO_do_connect(bio) <= 0) {
        std::printf("[-] connect failed\n");
        return 1;
    }

    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        char* subj = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
        char* iss  = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);
        std::printf("Subject: %s\nIssuer:  %s\n", subj, iss);
        OPENSSL_free(subj); OPENSSL_free(iss);
        X509_free(cert);
    }
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return 0;
}
