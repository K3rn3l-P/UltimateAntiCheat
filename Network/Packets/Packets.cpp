#include "Packets.hpp"

PacketWriter* Packets::Builder::ClientHello(
    const std::string& encryptedGameCode,
    const std::string& hardwareId,
    const std::string& hostname,
    const std::string& mac,
    const std::string& exeHash,
    const std::string& updaterHash,
    const std::string& duffDllHash,
    const std::string& dacHash)
{
    PacketWriter* p = new PacketWriter(Opcodes::CS::CS_HELLO);
    p->Write(static_cast<uint16_t>(encryptedGameCode.size()));
    p->WriteNoLengthString(encryptedGameCode);
    p->Write(static_cast<uint16_t>(hardwareId.size()));
    p->WriteNoLengthString(hardwareId);
    p->Write(static_cast<uint16_t>(hostname.size()));
    p->WriteNoLengthString(hostname);
    p->Write(static_cast<uint16_t>(mac.size()));
    p->WriteNoLengthString(mac);
    p->Write(static_cast<uint16_t>(exeHash.size()));
    p->WriteNoLengthString(exeHash);
    p->Write(static_cast<uint16_t>(updaterHash.size()));
    p->WriteNoLengthString(updaterHash);
    p->Write(static_cast<uint16_t>(duffDllHash.size()));
    p->WriteNoLengthString(duffDllHash);
    p->Write(static_cast<uint16_t>(dacHash.size()));
    p->WriteNoLengthString(dacHash);
    return p;
}

PacketWriter* Packets::Builder::ClientGoodbye(int reason)
{
    PacketWriter* p = new PacketWriter(Packets::Opcodes::CS_GOODBYE);
    p->Write<int>(reason);
    return p;
}

PacketWriter* Packets::Builder::DetectedCheater(int flags) //todo: finish these
{
    PacketWriter* p = new PacketWriter(Packets::Opcodes::CS_FLAGGED_CHEATER);
    p->Write<int>(flags);
    return p;
}

/*
    DetectedCheater - flag a user as cheating, with some string data about what it found
*/
PacketWriter* Packets::Builder::DetectedCheater(__in const uint32_t flags, __in const  const std::string detectedModule, __in const DWORD pid)
{
    PacketWriter* p = new PacketWriter(Packets::Opcodes::CS_FLAGGED_CHEATER);
    p->Write<uint32_t>(flags);
    p->Write<uint32_t>(pid);
    p->WriteString(detectedModule);
    return p;
}

PacketWriter* Packets::Builder::Heartbeat(const char* cookie_str) //todo: add more into this packet, such as integrity checking or detected flags.
{
    PacketWriter* p = new PacketWriter(Packets::Opcodes::CS_HEARTBEAT);
    p->WriteString(cookie_str);
    return p;
}

PacketWriter* Packets::Builder::QueryMemory(byte* bytestring, int size)
{
    PacketWriter* p = new PacketWriter(Packets::Opcodes::CS_QUERY_MEMORY);
    p->Write<uint16_t>(size);

    for (int i = 0; i < size; i++)
    {
        p->Write<BYTE>(bytestring[i]);
    }

    return p;
}