/*
    U.A.C. is a non-invasive usermode anticheat for x64 Windows, tested on Windows 10 & 11. Usermode is used to ensure an optimal end user experience. It also provides insight into how many kernelmode attack methods can be prevented from usermode, through concepts such as secure boot enforcement and DSE checking.

    Please view the readme for more information regarding program features. If you'd like to use this project in your game/software, please contact the author.

    License: GNU Affero general public license, please be aware of what and what not can be done with this license.. ** you do not have the right to copy this project into your closed-source, for-profit project **

    Author: AlSch092 @ Github
*/

#include "API/API.hpp"
#include "AntiCheat.hpp"
#include "SplashScreen.hpp"
#include "AntiTamper/MapProtectedClass.hpp" //to make Settings class object write-protected (see https://github.com/AlSch092/RemapProtectedClass)
#include "Obscure/XorStr.hpp"
#include <locale>
#include <codecvt>
#include <conio.h>
#include <tlhelp32.h>
#include <windows.h>
#include <set>
#include <string>
#include <iostream>
#include <fstream>
#include "Common/SHA256.hpp"
#include "Common/sha256_hashes.hpp" // inserisci subito dopo gli altri include
#include "Network/NetClient.hpp"
#include <memory>
#define OBFUSCATE(str) make_encrypted(L##str)
#include "Common/SHA256Utils.hpp"

// Usa direttamente le costanti importate
// const std::string expectedUpdaterSha256 = ... // RIMUOVI queste righe
// const std::string expectedDuffDllSha256 = ...
// const std::string expectedX32Sha256 = ...

bool VerifySelfChecksum(const std::wstring& filePath, const std::string& expectedSha256) {
    std::string actual = CalculateFileSHA256(filePath);
    return _stricmp(actual.c_str(), expectedSha256.c_str()) == 0;
}
// PER ORA COMMENTA PER DEBUG!
/*
bool CheckRootFolderIntegrity(const std::wstring& rootPath) {
    // Elenco dei file e cartelle obbligatori (senza game.log)
    const std::set<std::wstring> expected = {
        L"Commands.txt", L"CONFIG.exe", L"CONFIG.INI", L"data.saf", L"data.sah", L"duff.dll", L"dxgi.dll",
        L"game.exe", L"gsConfig.cfg", L"ijl15.dll", L"Log.txt", L"notice.txt", L"reshade-shaders.7z", L"public.der",
        L"ReShade.ini", L"ReShade.log", L"ReShade.log1", L"ReShadePreset.ini", L"splash.png", L"tip.txt", L"proxy.log",
        L"Updater.exe", L"Version.ini", L"x32.exe", L"libcurl-d.dll", L"zlibd1.dll", L"reshade-shaders", L"SCREENSHOT"
    };

    // File opzionali che possono esserci o meno
    const std::set<std::wstring> optional = {
        L"game.log"
    };

    // Cartelle che possono contenere file dinamici e NON vanno controllate nel loro interno
    const std::set<std::wstring> allowedDirsWithDynamicContent = {
        L"reshade-shaders", L"SCREENSHOT"
    };

    std::set<std::wstring> found;

    std::wstring searchPath = rootPath + L"\\*";
    WIN32_FIND_DATAW ffd;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &ffd);

    if (hFind == INVALID_HANDLE_VALUE)
        return false;

    do {
        std::wstring name = ffd.cFileName;
        if (name == L"." || name == L"..")
            continue;
        found.insert(name);
    } while (FindNextFileW(hFind, &ffd) != 0);

    FindClose(hFind);

    // Controlla che non ci siano file/cartelle non attesi (escludendo quelli opzionali)
    for (const auto& f : found) {
        if (expected.find(f) == expected.end() && optional.find(f) == optional.end()) {
            std::wcerr << L"[ERRORE] File/cartella non atteso: " << f << std::endl;
            return false;
        }
    }
    // Controlla che tutti i file obbligatori siano presenti
    for (const auto& f : expected) {
        if (found.find(f) == found.end()) {
            std::wcerr << L"[ERRORE] File/cartella mancante: " << f << std::endl;
            return false;
        }
    }
    return true;
}*/


#pragma comment(linker, "/ALIGN:0x10000") //for remapping technique (anti-tamper) - each section gets its own region, align with system allocation granularity
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")

HANDLE CreateKillOnCloseJob()
{
    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    if (hJob == NULL)
        return NULL;

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = { 0 };
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
    return hJob;
}

using namespace std;

void NTAPI __stdcall TLSCallback(PVOID pHandle, DWORD dwReason, PVOID Reserved);

EXTERN_C
#ifdef _M_X64
#pragma const_seg (".CRT$XLB") //store tls callback inside the correct section
const
#endif

PIMAGE_TLS_CALLBACK _tls_callback = TLSCallback;
#pragma data_seg ()
#pragma const_seg ()

Settings* Settings::Instance = nullptr; //singleton-style instance of Settings class, which will be made write-protected via ProtectedMemory class

void TerminateOtherGameInstances(DWORD currentPid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, L"x32.exe") == 0 && pe32.th32ProcessID != currentPid) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                if (hProc) {
                    TerminateProcess(hProc, 1);
                    CloseHandle(hProc);
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
}

bool SupressingNewThreads = true; //we need some variables in both our TLS callback and main()

LONG WINAPI g_ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo);

int main(int argc, char** argv)
{
    std::string userKeyboardInput; //for looping until user wants to exit

    std::wstring rootPath = L".";
    // Controllo integrità della cartella root (commentato per debug)
   /* if (!CheckRootFolderIntegrity(rootPath)) {
        std::wcerr << L"[ERRORE] Integrità della cartella root fallita. L'applicazione verrà chiusa." << std::endl;
        ExitProcess(1);
    }*/
    // FINE: Controllo integrità della cartella root (commentato per debug)

    // Updater: script per SHA256
    /*param(
        [string]$FilePath = "Updater.exe"
    )

    if (-Not (Test-Path $FilePath)) {
        Write-Error "File non trovato: $FilePath"
        exit 1
    }

    # Calcola SHA-256
    $hash = Get-FileHash -Path $FilePath -Algorithm SHA256

    # Copia negli appunti solo l'hash
    $hash.Hash | Set-Clipboard

    # Output di conferma
    Write-Host "SHA-256 hash per '$FilePath': $($hash.Hash)"
    Write-Host "L'hash è stato copiato negli appunti."
    pause
    */ //FINE
    // Controllo SHA256 Updater.exe 
    std::wstring updaterPath = L".\\Updater.exe";
    if (!VerifySelfChecksum(updaterPath, expectedUpdaterSha256)) {
        std::wcerr << L"[ERRORE] Updater.exe non valido! SHA256 mismatch. L'applicazione verrà chiusa." << std::endl;
        ExitProcess(1);
    }

    // SHA256 atteso di duff.dll (sostituisci con quello reale)
    std::wstring duffDllPath = L".\\duff.dll";
    if (!VerifySelfChecksum(duffDllPath, expectedDuffDllSha256)) {
        std::wcerr << L"[ERRORE] duff.dll non valido! SHA256 mismatch. L'applicazione verrà chiusa." << std::endl;
        ExitProcess(1);
    }

    std::unordered_map<DetectionFlags, const char*> explanations;
    std::list<DetectionFlags> flags; //for explanation output after the program is finished running

    // Set default options
#ifdef _DEBUG //in debug compilation, we are more lax with our protections for easier testing purposes
    const bool bEnableNetworking = true;  //change this to false if you don't want to use the server
    const bool bEnforceSecureBoot = false;
    const bool bEnforceDSE = true;
    const bool bEnforceNoKDBG = true;
    const bool bUseAntiDebugging = true;
    const bool bUseIntegrityChecking = true;
    const bool bCheckThreadIntegrity = true;
    const bool bCheckHypervisor = false;
    const bool bRequireRunAsAdministrator = true;
    const bool bUsingDriver = false; //signed driver for hybrid KM + UM anticheat. the KM driver will not be public, so make one yourself if you want to use this option  
    const bool bEnableLogging = true;

    const std::list<std::wstring> allowedParents = { L"VsDebugConsole.exe", L"vsdbg.exe", L"powershell.exe", L"bash.exe", L"zsh.exe", L"explorer.exe", L"x32.exe", L"Updater.exe" };
    const std::string logFileName = "game.log";

#else
    const bool bEnableNetworking = true; //change this to false if you don't want to use the server
    const bool bEnforceSecureBoot = false; //secure boot is recommended in distribution builds
    const bool bEnforceDSE = true;
    const bool bEnforceNoKDBG = true;
    const bool bUseAntiDebugging = true;
    const bool bUseIntegrityChecking = true;
    const bool bCheckThreadIntegrity = true;
    const bool bCheckHypervisor = false;
    const bool bRequireRunAsAdministrator = true;
    const bool bUsingDriver = false; //signed driver for hybrid KM + UM anticheat. the KM driver will not be public, so make one yourself if you want to use this option
    const bool bEnableLogging = false; // set to false to not create a detailed AntiCheat log file on the user's system

    constexpr auto parent_1 = OBFUSCATE("Updater.exe"); //in release build we can encrypt any compiled strings and decrypt them at runtime
    wchar_t decrypted_1[parent_1.getSize()] = {};
    parent_1.decrypt(decrypted_1);

    const std::list<std::wstring> allowedParents = { decrypted_1 }; //add your launcher here
	const std::string logFileName = "game.log"; //empty : does not log to file (game.log), otherwise logs to file with this name
#endif

#ifdef _DEBUG

    cout << "Settings for this instance:\n";
    cout << "\t Enable Networking:\t" << boolalpha << bEnableNetworking << endl;
    cout << "\t Enforce Secure Boot: \t" << boolalpha << bEnforceSecureBoot << endl;
    cout << "\t Enforce DSE:\t\t" << boolalpha << bEnforceDSE << endl;
    cout << "\t Enforce No KDBG:\t" << boolalpha << bEnforceNoKDBG << endl;
    cout << "\t Use Anti-Debugging:\t" << boolalpha << bUseAntiDebugging << endl;
    cout << "\t Use Integrity Checking:\t" << boolalpha << bUseIntegrityChecking << endl;
    cout << "\t Check Thread Integrity:\t" << boolalpha << bCheckThreadIntegrity << endl;
    cout << "\t Check Hypervisor:\t" << boolalpha << bCheckHypervisor << endl;
    cout << "\t Require Admin:\t\t" << boolalpha << bRequireRunAsAdministrator << endl;
    cout << "\t Using Kernelmode Driver:\t\t" << boolalpha << bUsingDriver << endl;
    cout << "\t Enable logging :\t\t" << boolalpha << bEnableLogging << endl;
    cout << "\t Allowed parent processes: \t\t" << endl;

    for (auto parent : allowedParents)
    {
        wcout << parent << " ";
    }

    cout << endl;

#endif

    HWND hWnd = GetConsoleWindow(); // serve in modalità Windows
    if (hWnd) ShowWindow(hWnd, SW_HIDE); // serve in modalità Windows

    // SetConsoleTitle(L"DAC"); // COMMENTATO: non serve in modalità Windows

    Thread* t = new Thread((LPTHREAD_START_ROUTINE)Splash::InitializeSplash, 0, false, true);

    cout << "*----------------------------------------------------------------------------------------*\n";
    cout << "|                           Welcome to Duff Anti-Cheat (DAC)!                            |\n";
    cout << "|    An in-development, non-commercial AC made to help teach concepts in game security   |\n";
    cout << "|                              Made by k3rn3l @Github                                    |\n";
    cout << "|         ...With special thanks to:                                                     |\n";
    cout << "|           AlSch092                                                                     |\n";
    cout << "|           discriminating (dll load notifcations, catalog verification)                 |\n";
    cout << "|           changeofpace (remapping method)                                              |\n";
    cout << "|           LucasParsy (testing, bug fixing)                                             |\n";
    cout << "*----------------------------------------------------------------------------------------*\n";

    std::unique_ptr<AntiCheat> Anti_Cheat = nullptr;

    ProtectedMemory ProtectedSettingsMemory(sizeof(Settings));

    Settings::Instance = ProtectedSettingsMemory.Construct<Settings>(
        bEnableNetworking,
        bEnforceSecureBoot,
        bEnforceDSE,
        bEnforceNoKDBG,
        bUseAntiDebugging,
        bUseIntegrityChecking,
        bCheckThreadIntegrity,
        bCheckHypervisor,
        bRequireRunAsAdministrator,
        bUsingDriver,
        allowedParents,
        bEnableLogging,
        logFileName);

    // --- QUI INSERISCI IL BLOCCO DI INIZIALIZZAZIONE DEL NETCLIENT ---


    // ABILITATO SOLO per test ed errori parental per l'updater.. SOLO TEST (ANCHE IN Detections/API.cpp)
    DWORD parentPid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    DWORD thisPid = GetCurrentProcessId();
    std::wstring parentProcessName = L"";

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == thisPid) {
                parentPid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    if (parentPid != 0) {
        // Cerca il nome del parent process
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == parentPid) {
                    parentProcessName = pe32.szExeFile;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
    }
    CloseHandle(hSnapshot);

    // Logga il nome del parent process
    Logger::logf(Info, "Parent process name: '%ws' (PID: %lu)", parentProcessName.c_str(), parentPid);

    // Controllo whitelist (case-insensitive)
    bool isAllowed = false;
    for (const auto& allowed : allowedParents) {
        if (_wcsicmp(parentProcessName.c_str(), allowed.c_str()) == 0) {
            isAllowed = true;
            break;
        }
    }
    if (!isAllowed) {
        std::wcerr << L"[ERRORE] Il client può essere avviato solo tramite il launcher Updater.exe! (Parent: '" << parentProcessName << L"')" << std::endl;
        Logger::logf(Err, "Parent process '%ws' was not whitelisted (expected Updater.exe), shutting down program!", parentProcessName.c_str());
        ExitProcess(1);
    }

    // ABILITATO SOLO per test ed errori parental per l'updater.. SOLO TEST (ANCHE IN Detections/API.cpp)
    // --- FINE BLOCCO CONTROLLO PARENT PROCESS ---

    try
    {
        ProtectedSettingsMemory.Protect(); //make the Settings object write-protect and resistant to page security changes
    }
    catch (const std::runtime_error& ex)
    {
        Logger::logf(Err, "Settings could not be initialized. Closing application...");
        return 1;
    }

    try
    {
        Anti_Cheat = std::make_unique<AntiCheat>(Settings::Instance, Services::GetWindowsVersion());   //after all environmental checks (secure boot, DSE, adminmode) are performed, create the AntiCheat object
    }
    catch (const std::bad_alloc& e)
    {
        Logger::logf(Err, "Anticheat pointer could not be allocated @ main(): %s", e.what());
        return 1;
    }
    catch (const AntiCheatInitFail& e)
    {
        Logger::logf(Err, "Anticheat init error: %d %s", e.reasonEnum, e.what());
        return 1;
    }

    if (Settings::Instance->bCheckThreads)
    {   //typically thread should cross-check eachother to ensure nothing is suspended, in this version of the program we only check thread suspends once at the start
        if (Anti_Cheat->IsAnyThreadSuspended()) //make sure that all our necessary threads aren't suspended by an attacker
        {
            Logger::logf(Detection, "Atleast one of our threads was found suspended! All threads must be running for proper module functionality.");
            return 1;
        }
    }

    SupressingNewThreads = Anti_Cheat->GetBarrier()->IsPreventingThreads(); //if this is set to TRUE, we can stop the creation of any new unknown threads via the TLS callback

    cout << "\n----------------------------------------------------------------------------------------------------------" << endl;
    cout << "All protections have been deployed, the program will now loop using its detection methods. Thanks for your interest in the project!" << endl;
    cout << "Please enter 'q' if you'd like to end the program." << endl;

    std::wstring exePath;
    if (argc >= 2) {
        exePath = std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().from_bytes(argv[1]);
    }
    else {
        exePath = L".\\x32.exe"; // Percorso relativo alla root Duff!_Client-v20
        std::wcout << L"[INFO] Nessun argomento fornito, avvio gioco di default: " << exePath << std::endl;
    }

    // Gioco: script per SHA256
    /*param(
        [string]$FilePath = "x32.exe"
    )

    if (-Not (Test-Path $FilePath)) {
        Write-Error "File non trovato: $FilePath"
        exit 1
    }

    # Calcola SHA-256
    $hash = Get-FileHash -Path $FilePath -Algorithm SHA256

    # Copia negli appunti solo l'hash
    $hash.Hash | Set-Clipboard

    # Output di conferma
    Write-Host "SHA-256 hash per '$FilePath': $($hash.Hash)"
    Write-Host "L'hash è stato copiato negli appunti."
    pause
    */ //FINE
    // GIOCO: SHA256 atteso di x32.exe (sostituisci con quello reale)
    // Verifica integrità x32.exe
    if (!VerifySelfChecksum(exePath, expectedX32Sha256)) {
        std::wcerr << L"[ERRORE] x32.exe non valido! SHA256 mismatch. L'applicazione verrà chiusa." << std::endl;
        ExitProcess(1);
    }

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    bool gameStarted = false;

    std::wstring commandLine = exePath + L" A9v1o 2X5Z";

    if (!exePath.empty()) {
        if (!CreateProcessW(
            nullptr,                // lpApplicationName: nullptr per usare commandLine
            &commandLine[0],        // lpCommandLine: deve essere modificabile
            nullptr, // lpProcessAttributes: nullptr per usare gli attributi di default
            nullptr, // lpThreadAttributes: nullptr per usare gli attributi di default
            FALSE, // bInheritHandles: FALSE per non ereditare gli handle
            0, // dwCreationFlags: 0 per usare le impostazioni di default
            nullptr, // lpEnvironment: nullptr per usare l'ambiente del processo chiamante
            nullptr, // lpCurrentDirectory: nullptr per usare la directory corrente
            &si,
            &pi))  // Crea il processo
        {
            std::wcerr << L"[ERROR] Failed to launch game executable: " << exePath << L" (error: " << GetLastError() << L")\n";
        }
        else {
            gameStarted = true;
            std::wcout << L"[INFO] Successfully launched: " << exePath << std::endl;

            // --- JOB OBJECT ---
            HANDLE hJob = CreateKillOnCloseJob();
            if (hJob && pi.hProcess) {
                AssignProcessToJobObject(hJob, pi.hProcess);
            }

            TerminateOtherGameInstances(pi.dwProcessId);
        }
    }

    DWORD lastCheck = GetTickCount();

    while (true)
    {
        // Se il gioco è stato avviato, controlla se è ancora attivo
        if (gameStarted && pi.hProcess) {
            DWORD result = WaitForSingleObject(pi.hProcess, 0);
            if (result == WAIT_OBJECT_0) {
                std::cout << "[INFO] Il gioco è stato chiuso. DAC si chiude..." << std::endl;
                break;
            }
        }

        // Ogni 2 secondi, termina eventuali altre istanze di x32.exe
        if (gameStarted) {
            if (GetTickCount() - lastCheck > 2000) {
                TerminateOtherGameInstances(pi.dwProcessId);
                lastCheck = GetTickCount();
            }
        }

        if (Anti_Cheat->GetMonitor()->IsUserCheater())
        {
            Logger::logf(Err, "Cheating process detected! Terminating...");

            // INVIA TUTTE LE DETECTION AL SERVER PRIMA DI TERMINARE
            if (Anti_Cheat->GetMonitor()->GetEvidenceLog() != nullptr)
            {
                Anti_Cheat->GetMonitor()->GetEvidenceLog()->PushAllEvidence();
                // Attendi brevemente per garantire l'invio
                Sleep(200);
            }

            if (gameStarted && pi.hProcess) {
                TerminateProcess(pi.hProcess, 1);
            }
            ExitProcess(1);
        }


        if (_kbhit()) {
            std::cin >> userKeyboardInput;
            if (userKeyboardInput == "q" || userKeyboardInput == "Q")
            {
                std::cout << "Exit key was pressed, shutting down program..." << std::endl;
                break;
            }
        }

        Sleep(100); // evita busy loop
    }
    // Prima del cleanup finale
    if (Anti_Cheat) {
        // Chiudi il thread di anti-debug
        if (auto antiDbg = Anti_Cheat->GetAntiDebugger()) {
            Thread* detectionThread = antiDbg->GetDetectionThread();
            if (detectionThread) {
                detectionThread->SignalShutdown(TRUE);
                detectionThread->JoinThread();
            }
        }
        // Chiudi altri thread se necessario (es. monitor)
        // ...
        // Chiudi la connessione di rete
        if (!Anti_Cheat->GetNetworkClient().expired()) {
            auto netClient = Anti_Cheat->GetNetworkClient().lock();
            if (netClient) {
                netClient->EndConnection(0);
            }
        }
    }
    // Se il gioco è stato avviato, attendi la chiusura del processo
    // Cleanup finale
    if (gameStarted) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }


#ifdef _DEBUG

    flags = Anti_Cheat->GetMonitor()->GetDetectedFlags();
    explanations =
    {
        { DetectionFlags::PAGE_PROTECTIONS, "Image's .text section is writable, memory was re-re-mapped" },
        { DetectionFlags::CODE_INTEGRITY, "Image's memory in .text or .rdata modified" },
        { DetectionFlags::DLL_TAMPERING, "Networking or certificate-related WINAPI hooked" },
        { DetectionFlags::BAD_IAT, "Import Adress Table entry points to memory outside loaded modules" },
        { DetectionFlags::OPEN_PROCESS_HANDLES, "A process has handles to our process" },
        { DetectionFlags::UNSIGNED_DRIVERS, "Unsigned drivers running on the machine" },
        { DetectionFlags::INJECTED_ILLEGAL_PROGRAM, "Unsigned DLL loaded into the process" },
        { DetectionFlags::EXTERNAL_ILLEGAL_PROGRAM, "Blacklisted program name running on machine" },
        { DetectionFlags::REGISTRY_KEY_MODIFICATIONS, "Changes to registry keys related to secure boot, CI, testsigning mode, etc..." },
        { DetectionFlags::MANUAL_MAPPING, "Manually mapped module written into memory" },
        { DetectionFlags::SUSPENDED_THREAD, "One or more important threads were suspended" },
        { DetectionFlags::HYPERVISOR, "A Hypervisor is running on the machine" },
        { DetectionFlags::DEBUG_WINAPI_DEBUGGER, "A debugging method was detected via `IsDebuggerPresent()`" },
        { DetectionFlags::DEBUG_PEB, "A debugging method was detected via `BeingDebugged` flag in the PEB" },
        { DetectionFlags::DEBUG_DBK64_DRIVER, "A debugging method was detected via DBK64.sys being loaded" },
        { DetectionFlags::DEBUG_CLOSEHANDLE, "A debugging method was detected via `CloseHandle(NULL)`" },
        { DetectionFlags::DEBUG_DEBUG_OBJECT, "A debugging method was detected via debug object" },
        { DetectionFlags::DEBUG_DEBUG_PORT, "A debugging method was detected via debug port" },
        { DetectionFlags::DEBUG_HEAP_FLAG, "A debugging method was detected via heap flags" },
        { DetectionFlags::DEBUG_KERNEL_DEBUGGER, "A debugging method was detected via OS-managed kernelmode debugging option" },
        { DetectionFlags::DEBUG_HARDWARE_REGISTERS, "A debugging method was detected via hardware debug registers" },
        { DetectionFlags::DEBUG_INT2C, "A debugging method was detected via INT 2C instruction" },
        { DetectionFlags::DEBUG_TRAP_FLAG, "A debugging method was detected via trap flag enabled" },
        { DetectionFlags::DEBUG_INT3, "A debugging method was detected via INT3 instruction" },
    };
    for (DetectionFlags flag : flags)
    {
        Logger::logf(Info, explanations[flag]);
    }
#endif

Cleanup:
    if (t != nullptr)
        delete t;

    Anti_Cheat.reset();
    ProtectedSettingsMemory.~ProtectedMemory();

    return 0;
}

/*
The TLS callback triggers on process + thread attachment & detachment, which means we can catch any threads made by an attacker in our process space.
We can end attacker threads using ExitThread(), and let in our threads which are managed.
...An attacker can circumvent this by modifying the pointers to TLS callbacks which the program usually keeps track of, which requires re-remapping
*/
void NTAPI __stdcall TLSCallback(PVOID pHandle, DWORD dwReason, PVOID Reserved)
{
    const UINT ThreadExecutionAddressStackOffset = 0x378; //** this might change on different version of window, Windows 10 is all I have access to currently

    static bool FirstProcessAttach = true;
    static bool SetExceptionHandler = false;
    static WindowsVersion WinVersion = WindowsVersion::ErrorUnknown;

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        if (!Preventions::StopMultipleProcessInstances()) //prevent multi-clients by using shared memory-mapped region
        {
            Logger::logf(Err, "Could not initialize program: shared memory check failed, make sure only one instance of the program is open. Shutting down.");
            terminate();
        }

		//Logger::logf(Info, " New process attached, current thread %d\n", GetCurrentThreadId()); // PROBLEMA CON WINMAIN: non funziona in modalità Windows, ma solo in console

        if (FirstProcessAttach) //process creation will trigger PROCESS_ATTACH, so we can put some initialize stuff in here incase main() is hooked or statically modified by the attacker
        {
            WinVersion = Services::GetWindowsVersion();

            if (!SetExceptionHandler)
            {
                SetUnhandledExceptionFilter(g_ExceptionHandler);

                if (!AddVectoredExceptionHandler(1, g_ExceptionHandler))
                {
                    Logger::logf(Err, " Failed to register Vectored Exception Handler @ TLSCallback: %d\n", GetLastError());
                }

                SetExceptionHandler = true;
            }

            FirstProcessAttach = false;
        }
        else
        {
            Logger::logf(Detection, " Some unknown process attached @ TLSCallback "); //this should generally never be triggered in this example
        }
    }break;

    case DLL_PROCESS_DETACH: //program exit, clean up any memory allocated if required
    {
    }break;

    case DLL_THREAD_ATTACH: //add to our thread list, or if thread is not executing valid address range, patch over execution address
    {
#ifndef _DEBUG
        if (!Debugger::AntiDebug::HideThreadFromDebugger(GetCurrentThread())) //hide thread from debuggers, placing this in the TLS callback allows all threads to be hidden
        {
            Logger::logf(Warning, " Failed to hide thread from debugger @ TLSCallback: thread id %d\n", GetCurrentThreadId());
        }
#endif

        if (SupressingNewThreads)
        {
            if (WinVersion == Windows11) //Windows 11 no longer has the thread's start address on the its stack, bummer. don't have a W11 machine either at home
                return;

            UINT64 ThreadExecutionAddress = *(UINT64*)((UINT64)_AddressOfReturnAddress() + ThreadExecutionAddressStackOffset); //check down the stack for the thread execution address, compare it to good module range, and if not in range then we've detected a rogue thread

            if (ThreadExecutionAddress == 0) //this generally should never be 0, but we'll add a check for good measure incase the offset changes on different W10 builds
                return;

            auto modules = Process::GetLoadedModules();

            for (auto module : modules)
            {
                UINT64 LowAddr = (UINT64)module.dllInfo.lpBaseOfDll;
                UINT64 HighAddr = (UINT64)module.dllInfo.lpBaseOfDll + module.dllInfo.SizeOfImage;

                if (ThreadExecutionAddress > LowAddr && ThreadExecutionAddress < HighAddr) //a properly loaded DLL is making the thread, so allow it to execute
                {
                    //if any unsigned .dll is loaded, it will be caught in the DLL load callback/notifications, so we shouldnt need to cert check in this routine (this will cause slowdowns in execution, also cert checking inside the TLS callback doesn't seem to work properly here)
                    return; //any manually mapped modules' threads will be stopped since they arent using the loader and thus won't be in the loaded modules list
                }
            }

            Logger::logf(Detection, " Stopping unknown thread from being created  @ TLSCallback: thread id %d", GetCurrentThreadId());
            Logger::logf(Detection, " Thread id %d wants to execute function @ %llX. Patching over this address.", GetCurrentThreadId(), ThreadExecutionAddress);

            DWORD dwOldProt = 0;

            if (!VirtualProtect((LPVOID)ThreadExecutionAddress, sizeof(byte), PAGE_EXECUTE_READWRITE, &dwOldProt)) //make thread start address writable
            {
                Logger::logf(Warning, "Failed to call VirtualProtect on ThreadStart address @ TLSCallback: %llX", ThreadExecutionAddress);
            }
            else
            {
                if (ThreadExecutionAddress != 0)
                {
                    *(BYTE*)ThreadExecutionAddress = 0xC3; //write over any functions which are scheduled to execute next by this thread and not inside our whitelisted address range
                }
            }
        }

    }break;

    case DLL_THREAD_DETACH:
    {
    }break;
    };
}

/*
    ExceptionHandler - User defined exception handler which catches program-wide exceptions
    ...Currently we are not doing anything special with this, but we'll leave it here incase we need it later
*/
LONG WINAPI g_ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo)  //handler that will be called whenever an unhandled exception occurs in any thread of the process
{
    DWORD exceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;

    if (exceptionCode != EXCEPTION_BREAKPOINT) //one or two of our debug checks may throw this exception
    {
        Logger::logf(Warning, "Program threw exception: %x at %llX\n", exceptionCode, ExceptionInfo->ExceptionRecord->ExceptionAddress);
    } //optionally we may be able to view the exception address and compare it to whitelisted module address space, if it's not contained then we assume it's attacker-run code

    return EXCEPTION_CONTINUE_SEARCH;
}

// WinMain
// Forward declaration
int main(int argc, char** argv);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    // Puoi parsare lpCmdLine se vuoi passare argomenti
    return main(__argc, __argv);
}
