#pragma once
#include "PacketWriter.hpp"
#include "PacketReader.hpp"
#include <list>
#include <stdint.h>

using namespace std;

namespace Packets
{
	namespace Opcodes
	{
		enum CS //client2server
		{
			CS_HELLO = 1,
			CS_GOODBYE, //there is no SC_GOODBYE
			CS_HEARTBEAT, //heartbeats will be a 128-length text string which must be determinated by the server. this means both client and server need to know how to generate the next valid response
			CS_INFO_LOGGING, //hostname + mac address + hardware ID
			CS_FLAGGED_CHEATER,
			CS_QUERY_MEMORY,
			CS_HASH_CHECK, // <--- AGGIUNGI QUESTO
			CS_CLIENTINFO_PERIODIC, // <--- AGGIUNGI QUESTO (allineamento con server)
		};

		enum SC //server2client
		{
			SC_HELLO = 1,
			SC_HEARTBEAT,
			SC_INFO_LOGGING,
			SC_FLAGGED_CHEATER,
			SC_QUERY_MEMORY,
			SC_HASH_CHECK_RESULT, // <--- AGGIUNGI QUESTO (opzionale)
		};
	}

	namespace Builder
	{
		PacketWriter* ClientGoodbye(int reason);
		PacketWriter* Heartbeat(const char* cookie_str);
		PacketWriter* DetectedCheater(int flags);
		PacketWriter* DetectedCheater(__in const uint32_t flags, __in const std::string detectedModule, __in const DWORD pid);
		PacketWriter* QueryMemory(byte* bytestring, int size);
		PacketWriter* ClientHello(const std::string& encryptedGameCode,
			const std::string& hardwareId,
			const std::string& hostname,
			const std::string& mac,
			const std::string& exeHash,
			const std::string& updaterHash,
			const std::string& duffDllHash,
			const std::string& dacHash);
		PacketWriter* ClientHashCheck(const std::string& exeHash,
			const std::string& updaterHash,
			const std::string& duffDllHash,
			const std::string& dacHash); // <--- AGGIUNGI QUESTO
		PacketWriter* ClientInfoPeriodic(const std::string& encryptedGameCode,
			const std::string& hardwareId,
			const std::string& hostname,
			const std::string& mac);
		PacketWriter* ClientFileHash(const std::string& fileHash);
	}
}
