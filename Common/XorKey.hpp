#pragma once
#include <string>
#include <fstream>

constexpr unsigned int xor_seed =
(__TIME__[0] * 3600 + __TIME__[1] * 60 + __TIME__[3] * 10 + __TIME__[4]) ^
(__DATE__[0] * 31 + __DATE__[1] * 12 + __DATE__[4]);

// Cambia nome per evitare conflitti con Obscure/XorStr.hpp
extern char XorNetworkKey[16];

std::string GetXorNetworkKey();
void ExportXorNetworkKeyToFile(const std::string& path = "xor_key.txt");
