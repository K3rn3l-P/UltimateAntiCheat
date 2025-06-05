#include "XorKey.hpp"

// Cambia nome per evitare conflitti
char XorNetworkKey[16] = {
    (char)((xor_seed >> 0) & 0xFF),
    (char)((xor_seed >> 1) & 0xFF),
    (char)((xor_seed >> 2) & 0xFF),
    (char)((xor_seed >> 3) & 0xFF),
    (char)((xor_seed >> 4) & 0xFF),
    (char)((xor_seed >> 5) & 0xFF),
    (char)((xor_seed >> 6) & 0xFF),
    (char)((xor_seed >> 7) & 0xFF),
    (char)((xor_seed >> 8) & 0xFF),
    (char)((xor_seed >> 9) & 0xFF),
    (char)((xor_seed >> 10) & 0xFF),
    (char)((xor_seed >> 11) & 0xFF),
    (char)((xor_seed >> 12) & 0xFF),
    (char)((xor_seed >> 13) & 0xFF),
    (char)((xor_seed >> 14) & 0xFF),
    (char)((xor_seed >> 15) & 0xFF)
};

std::string GetXorNetworkKey() { return std::string(XorNetworkKey, 16); }

void ExportXorNetworkKeyToFile(const std::string& path) {
    std::ofstream ofs(path, std::ios::binary);
    ofs.write(XorNetworkKey, 16);
}
