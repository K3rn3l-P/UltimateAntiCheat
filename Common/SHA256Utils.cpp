// Common/SHA256Utils.cpp
#include "SHA256Utils.hpp"
#include "SHA256.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>

std::string CalculateFileSHA256(const std::wstring& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file)
        return "";

    SHA256 sha;
    std::vector<uint8_t> buffer(4096);
    while (file) {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize bytesRead = file.gcount();
        if (bytesRead > 0)
            sha.update(buffer.data(), static_cast<size_t>(bytesRead));
    }
    uint8_t* digest = sha.digest();
    std::ostringstream oss;
    for (int i = 0; i < 32; ++i)
        oss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    delete[] digest;
    return oss.str();
}
