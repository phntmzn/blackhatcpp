// ============================================================
// codesign_check.cpp — verify code signature of a binary
// ------------------------------------------------------------
// Compile: clang++ -O2 -o codesign_check codesign_check.cpp -framework Security -framework CoreFoundation
// Usage:   ./codesign_check /bin/ls
// ============================================================
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        kCFAllocatorDefault, (const UInt8*)argv[1], strlen(argv[1]), false);

    SecStaticCodeRef code = nullptr;
    OSStatus st = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    if (st != errSecSuccess) { fprintf(stderr, "create failed %d\n", (int)st); return 1; }

    st = SecStaticCodeCheckValidity(code, kSecCSDefaultFlags, nullptr);
    printf("%s: %s\n", argv[1], st == errSecSuccess ? "VALID" : "INVALID");
    return 0;
}
