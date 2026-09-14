// ============================================================
// macho_parse.cpp — parse Mach-O load commands
// ------------------------------------------------------------
// Compile: clang++ -O2 -o macho_parse macho_parse.cpp
// Usage:   ./macho_parse /bin/ls
// ============================================================
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 1;

    uint32_t magic;
    fread(&magic, 4, 1, f);
    rewind(f);

    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        printf("FAT binary\n");
        return 0;
    }

    struct mach_header_64 hdr;
    fread(&hdr, sizeof(hdr), 1, f);
    printf("cputype=%d ncmds=%u sizeofcmds=%u\n",
           hdr.cputype, hdr.ncmds, hdr.sizeofcmds);

    for (uint32_t i = 0; i < hdr.ncmds; i++) {
        struct load_command lc;
        fread(&lc, sizeof(lc), 1, f);
        printf("  cmd=0x%x size=%u\n", lc.cmd, lc.cmdsize);
        fseek(f, lc.cmdsize - sizeof(lc), SEEK_CUR);
    }
    fclose(f);
    return 0;
}
