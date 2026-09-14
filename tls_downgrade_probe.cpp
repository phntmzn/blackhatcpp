// ============================================================
// tls_downgrade_probe.cpp — offer only weak versions
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o tls_downgrade_probe tls_downgrade_probe.cpp \
//          -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib \
//          -lssl -lcrypto
// Usage:   ./tls_downgrade_probe <host> <port>
// ============================================================
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 3) return 1;
    SSL_library_init();
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

    BIO* bio = BIO_new_ssl_connect(ctx);
    SSL* ssl = nullptr;
    BIO_get_ssl(bio, &ssl);
    SSL_set_tlsext_host_name(ssl, argv[1]);
    BIO_set_conn_hostname(bio, (std::string(argv[1]) + ":" + argv[2]).c_str());

    int r = BIO_do_connect(bio);
    std::printf("connect: %d\n", r);
    if (r > 0) {
        std::printf("version: %s\n", SSL_get_version(ssl));
        std::printf("cipher:  %s\n", SSL_get_cipher(ssl));
    }
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return 0;
}
