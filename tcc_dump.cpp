// ============================================================
// tcc_dump.cpp — dump TCC permissions from user DB
// ------------------------------------------------------------
// Compile: clang++ -O2 -o tcc_dump tcc_dump.cpp -lsqlite3
// Run:     ./tcc_dump
// Note:    Full Disk Access required to read TCC.db on modern macOS.
// ============================================================
#include <sqlite3.h>
#include <cstdio>
#include <cstdlib>

int main() {
    const char* home = getenv("HOME");
    char path[512];
    snprintf(path, sizeof(path),
        "%s/Library/Application Support/com.apple.TCC/TCC.db", home);

    sqlite3* db;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        fprintf(stderr, "open failed (need Full Disk Access)\n");
        return 1;
    }

    sqlite3_exec(db,
        "SELECT service, client, auth_value FROM access;",
        [](void*, int n, char** v, char**) {
            for (int i = 0; i < n; i++) printf("%s ", v[i] ? v[i] : "NULL");
            printf("\n");
            return 0;
        }, nullptr, nullptr);
    sqlite3_close(db);
    return 0;
}
