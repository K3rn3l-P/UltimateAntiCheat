//By AlSch092 @ Github
#include "API.hpp"
#include "../AntiCheat.hpp"
#include <random>
#include <sstream>
#include <iomanip>
#include <chrono>
#include "../Common/XorKey.hpp"
#include <vector>
#include <string>

std::string XorEncryptAdvanced(const std::string& input, const std::string& key)
{
	std::string output = input;
	for (size_t i = 0; i < input.size(); ++i)
	{
		// XOR + rotazione + offset per maggiore offuscamento
		output[i] = (input[i] ^ key[i % key.size()]) + (char)(i % 7);
		output[i] = (output[i] << ((i % 3) + 1)) | (output[i] >> (8 - ((i % 3) + 1)));
	}
	return output;
}

static std::string GenerateRandomGameCode()
{
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 255);

	unsigned char uuid[16];
	for (int i = 0; i < 16; ++i)
		uuid[i] = static_cast<unsigned char>(dis(gen));

	// Set version (4) and variant bits per RFC 4122
	uuid[6] = (uuid[6] & 0x0F) | 0x40;
	uuid[8] = (uuid[8] & 0x3F) | 0x80;

	// Timestamp
	auto now = std::chrono::system_clock::now().time_since_epoch();
	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();

	std::ostringstream oss;
	oss << "GAMECODE-";
	for (int i = 0; i < 16; ++i) {
		oss << std::hex << std::setw(2) << std::setfill('0') << (int)uuid[i];
		if (i == 3 || i == 5 || i == 7 || i == 9)
			oss << "-";
	}
	oss << "-" << ms;
	return oss.str();
}

/*
	Initialize - Initializes the anti-cheat module by connecting to the auth server (if available) and sending it the game's unique code, and checking the parent process to ensure a rogue launcher wasn't used
	returns Error::OK on success.
*/
Error API::Initialize(AntiCheat* AC, string licenseKey, bool isServerAvailable)
{
	Error errorCode = Error::OK;
	bool isLicenseValid = false;

	if (AC == NULL)
		return Error::NULL_MEMORY_REFERENCE;

	std::list<wstring> allowedParents = AC->GetConfig()->allowedParents;
	std::wstring realParentName = Process::GetProcessName(Process::GetParentProcessId());
	Logger::logfw(Info, L"Parent process effettivo: '%ws'", realParentName.c_str());

	bool found = false;
	for (const auto& allowed : allowedParents) {
		if (_wcsicmp(realParentName.c_str(), allowed.c_str()) == 0) {
			found = true;
			break;
		}
	}
	// INIZIO:Disabilita il controllo parent process qui per TEST (ANCHE IN Detections.cpp)

	if (found) {
		AC->GetMonitor()->GetProcessObj()->SetParentName(realParentName);
	}
	else {
		Logger::logfw(Detection, L"Parent process '%ws' was not whitelisted, shutting down program!", realParentName.c_str());
		errorCode = Error::PARENT_PROCESS_MISMATCH;
	}

	// FINE: Disabilita il controllo parent process qui per TEST (ANCHE IN Detections.cpp)

	if (isServerAvailable)
	{
		Logger::logf(Info, "Starting networking component...");

		auto client = AC->GetNetworkClient().lock();

		if (client)
		{
			if (client->Initialize(API::ServerEndpoint, API::ServerPort, licenseKey) != Error::OK) //initialize client is separate from license key auth
			{
				errorCode = Error::CANT_STARTUP;		//don't allow AC startup if network portion doesn't succeed
				goto end;
			}
		}
		else
		{
			Logger::logf(Err, "Could not fetch/lock network client, exiting...");
			return Error::NULL_MEMORY_REFERENCE;
		}
	}
	else
	{
		Logger::logf(Info, "Networking is currently disabled, no heartbeats will occur");
	}

end:
	return errorCode;
}

/*
	Cleanup - signals thread shutdowns and deletes memory associated with the Anticheat* object `AC`
	returns Error::OK on success
*/
Error API::Cleanup(AntiCheat* AC)
{
	if (AC == nullptr)
		return Error::NULL_MEMORY_REFERENCE;

	if (AC->GetConfig()->bUseAntiDebugging && AC->GetAntiDebugger() != nullptr && AC->GetAntiDebugger()->GetDetectionThread() != nullptr) //stop anti-debugger thread
	{
		AC->GetAntiDebugger()->GetDetectionThread()->SignalShutdown(true);
		AC->GetAntiDebugger()->GetDetectionThread()->JoinThread();
	}

	if (AC->GetMonitor() != nullptr && AC->GetMonitor()->GetMonitorThread() != nullptr) //stop anti-cheat monitor thread
	{
		AC->GetMonitor()->GetMonitorThread()->SignalShutdown(true);
		AC->GetMonitor()->GetMonitorThread()->JoinThread();
	}

	if (AC->GetMonitor() != nullptr && AC->GetMonitor()->GetProcessCreationMonitorThread() != nullptr) //stop process creation monitor thread
	{
		AC->GetMonitor()->GetProcessCreationMonitorThread()->SignalShutdown(true);
		AC->GetMonitor()->GetProcessCreationMonitorThread()->JoinThread();
	}

	if (AC->GetMonitor() != nullptr && AC->GetMonitor()->GetRegistryMonitorThread() != nullptr) //stop registry monitor
	{
		AC->GetMonitor()->GetRegistryMonitorThread()->SignalShutdown(true);
		AC->GetMonitor()->GetRegistryMonitorThread()->JoinThread();
	}

	auto client = AC->GetNetworkClient().lock();

	if (client)
	{
		if (client->GetRecvThread() != nullptr) //stop anti-cheat monitor thread
		{
			client->GetRecvThread()->SignalShutdown(true);
			client->GetRecvThread()->JoinThread();
		}
	}
	else
	{
		Logger::logf(Err, "Couldn't fetch/lock netclient @  API::Cleanup");
		return Error::NULL_MEMORY_REFERENCE;
	}

	return Error::OK;
}

/*
	LaunchDefenses - Initialize detections, preventions, and ADbg techniques
	returns Error::OK on success
*/
Error API::LaunchDefenses(AntiCheat* AC) //currently in the process to split these tests into Detections or Preventions
{
	if (AC == nullptr || AC->GetMonitor() == nullptr || AC->GetAntiDebugger() == nullptr || AC->GetBarrier() == nullptr)
		return Error::NULL_MEMORY_REFERENCE;

	Error errorCode = Error::OK;

	if (AC->GetBarrier()->DeployBarrier() == Error::OK) //activate all techniques to stop cheaters
	{
		Logger::logf(Info, " Barrier techniques were applied successfully!");
	}
	else
	{
		Logger::logf(Err, "Could not initialize the barrier @ API::LaunchBasicTests");
		errorCode = Error::CANT_APPLY_TECHNIQUE;
	}

	if (!AC->GetMonitor()->StartMonitor()) //start looped detections
	{
		Logger::logf(Err, "Could not initialize the barrier @ API::LaunchBasicTests");
		errorCode = Error::CANT_STARTUP;
	}

	AC->GetAntiDebugger()->StartAntiDebugThread(); //start debugger checks in a seperate thread

	//AC->GetMonitor()->GetServiceManager()->GetServiceModules(); //enumerate services -> currently not in use

	// INIZIO: Disabilita il controllo parent process qui per TEST (ANCHE IN Detections.cpp)

	std::wstring parentName = AC->GetMonitor()->GetProcessObj()->GetParentName();
	bool requireSignature = true;
	if (_wcsicmp(parentName.c_str(), L"Updater.exe") == 0) {
		requireSignature = false;
	}
	if (!Process::CheckParentProcess(parentName, requireSignature)) {
		Logger::logf(Detection, "Parent process was not in whitelist!");
		errorCode = Error::PARENT_PROCESS_MISMATCH;
	}

	// FINE: Disabilita il controllo parent process qui per TEST (ANCHE IN Detections.cpp)
	return errorCode;
}

/*
	Dispatch - handles sending requests through the AntiCheat class `AC`, mainly for initialization & cleanup
	returns Error::OK on successful execution
*/
Error API::Dispatch(AntiCheat* AC, DispatchCode code)
{
	Error errorCode = Error::OK;

	switch (code)
	{
	case INITIALIZE:
	{
		std::string gameCode = GenerateRandomGameCode();
		std::string xorKey = GetXorNetworkKey();
		std::string encryptedGameCode = XorEncryptAdvanced(gameCode, xorKey);
		// invio encryptedGameCode al server

		errorCode = Initialize(AC, gameCode, AC->GetConfig()->bNetworkingEnabled);

		if (errorCode == Error::OK)
		{
			if (LaunchDefenses(AC) != Error::OK)
			{
				Logger::logf(Warning, " At least one technique experienced abnormal behavior when launching tests.");
				return Error::CANT_APPLY_TECHNIQUE;
			}
		}
		else
		{
			Logger::logf(Warning, "Couldn't start up, either the parent process was wrong or no auth server was present.");
			return Error::CANT_CONNECT;
		}
	}
	break;


	case CLIENT_EXIT:
	{
		Error err = Cleanup(AC); //clean up memory, shut down any threads

		if (err == Error::OK)
		{
			errorCode = Error::OK;
		}
		else
		{
			errorCode = Error::NULL_MEMORY_REFERENCE;
		}
	} break;

	default:
		Logger::logf(Warning, "Unrecognized dispatch code @ API::Dispatch: %d\n", code);
		break;
	};

	return errorCode;
}