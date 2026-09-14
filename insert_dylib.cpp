// ============================================================
// insert_dylib.cpp — add LC_LOAD_DYLIB to Mach-O binary
// ------------------------------------------------------------
// Compile: clang++ -std=c++17 -O2 -o insert_dylib insert_dylib.cpp
// Usage:   ./insert_dylib <binary> <dylib_path>
// ============================================================
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <cstdio>
#include <cstring>
#include <string>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::printf("usage: %s <bin> <dylib>\n", argv[0]);
        return 1;
    }

    FILE* f = fopen(argv[1], "r+b");
    if (!f) return 1;

    mach_header_64 hdr{};
    fread(&hdr, sizeof(hdr), 1, f);

    uint32_t end = sizeof(hdr);
    for (uint32_t i = 0; i < hdr.ncmds; i++) {
        load_command lc{};
        fseek(f, end, SEEK_SET);
        fread(&lc, sizeof(lc), 1, f);
        end += lc.cmdsize;
    }

    uint32_t avail = hdr.sizeofcmds - (end - static_cast<uint32_t>(sizeof(hdr)));
    uint32_t need  = sizeof(dylib_command) + static_cast<uint32_t>(std::strlen(argv[2])) + 1;

    if (avail < need) {
        std::printf("[-] not enough padding: need %u, have %u\n", need, avail);
        fclose(f);
        return 1;
    }

    dylib_command dc{};
    dc.cmd = LC_LOAD_DYLIB;
    dc.cmdsize = need;
    dc.dylib.name.offset = sizeof(dc);
    dc.dylib.timestamp = 0;
    dc.dylib.current_version = 0x10000;
    dc.dylib.compatibility_version = 0x10000;

    fseek(f, end, SEEK_SET);
    fwrite(&dc, sizeof(dc), 1, f);
    fwrite(argv[2], std::strlen(argv[2]) + 1, 1, f);

    hdr.ncmds++;
    hdr.sizeofcmds += need;
    fseek(f, 0, SEEK_SET);
    fwrite(&hdr, sizeof(hdr), 1, f);

    fclose(f);
    std::printf("[+] injected %s into %s\n", argv[2], argv[1]);
    return 0;
}
