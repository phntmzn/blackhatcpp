// ============================================================
// xor_crypt.cpp — XOR buffer cipher (shellcode obfuscation)
// ------------------------------------------------------------
// Compile: clang++ -O2 -o xor_crypt xor_crypt.cpp
// Run:    ./xor_crypt
// ============================================================
#include <cstdio>
#include <cstring>

void xorBuf(char* b, size_t n, char k) {
    for (size_t i = 0; i < n; i++) b[i] ^= k;
}

int main() {
    char data[] = "Hello, shellcode!";
    xorBuf(data, strlen(data), 0x5A);
    xorBuf(data, strlen(data), 0x5A);
    printf("%s\n", data);
    return 0;
}
