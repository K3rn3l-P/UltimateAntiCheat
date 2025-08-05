//UltimateAnticheat Server - By AlSch092 @ Github

using System;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using Newtonsoft.Json;
using System.IO.Compression;

namespace UACServer.Network
{
    internal class Handlers
    {
        // Limite massimo estrazioni special.patch
        private static int SpecialPatchExtractCount = 0;
        private const int MaxSpecialPatchExtract = 3;

        // Funzione di sincronizzazione automatica hash
        private static bool TrySyncHashFolder()
        {
            if (SpecialPatchExtractCount >= MaxSpecialPatchExtract)
                return false;
            try
            {
                string patchPath = @"C:\xampp\htdocs\shaiya\patch\special.patch";
                string hashFolder = @"C:\DAC-Server\hash";
                string updaterExe = Path.Combine(hashFolder, "Updater.exe");
                if (File.Exists(patchPath))
                {
                    // Cancella tutti i file nella cartella hash tranne Updater.exe
                    if (Directory.Exists(hashFolder))
                    {
                        foreach (var file in Directory.GetFiles(hashFolder))
                        {
                            if (string.Equals(Path.GetFileName(file), "Updater.exe", StringComparison.OrdinalIgnoreCase))
                                continue; // NON eliminare Updater.exe
                            try { File.Delete(file); } catch { }
                        }
                    }
                    else
                    {
                        Directory.CreateDirectory(hashFolder);
                    }
                    // Estrai senza parametro overwrite
                    ZipFile.ExtractToDirectory(patchPath, hashFolder);
                    Logger.LogInfoTag("DACServer.log", $"[SYNC] Estratta special.patch in {hashFolder}");
                    SpecialPatchExtractCount++;
                    return true;
                }
            }
            catch (Exception ex)
            {
                Logger.LogError("DACServer.log", $"[ERROR][SYNC] Impossibile estrarre special.patch: {ex}");
            }
            return false;
        }

        public static bool HandleClientHello(AntiCheatClient c, PacketReader p, out string failReason, out bool alreadyLogged, bool hasRetriedSync = false) //hardwareID, hostname, MAC addr as fields
        {
            failReason = null;
            alreadyLogged = false;

            ushort gamecode_len = p.ReadUShort();
            string encrypted_gamecode = p.ReadString(gamecode_len);
            string xorKey = GetXorKey();
            string gamecode = XorDecryptAdvanced(encrypted_gamecode, xorKey);

            ushort hardware_id_len = p.ReadUShort();
            string hardware_id = p.ReadString(hardware_id_len);

            ushort hostname_len = p.ReadUShort();
            string hostname = p.ReadString(hostname_len);

            ushort MAC_len = p.ReadUShort();
            string MAC = p.ReadString(MAC_len);

            // --- LEGGI HASH ---
            ushort hash_len = p.ReadUShort();
            string exeHash = p.ReadString(hash_len);
            ushort updater_hash_len = p.ReadUShort();
            string updaterHash = p.ReadString(updater_hash_len);
            ushort duff_hash_len = p.ReadUShort();
            string duffDllHash = p.ReadString(duff_hash_len);
            ushort dac_hash_len = p.ReadUShort();
            string dacHash = p.ReadString(dac_hash_len);

            if (hardware_id_len == 0 || hostname_len == 0 || MAC_len == 0 || hash_len == 0 || updater_hash_len == 0 || duff_hash_len == 0 || dac_hash_len == 0)
            {
                failReason = "Uno o più campi obbligatori sono vuoti";
                return false;
            }

            c.hardware_id = hardware_id;
            c.hostname = hostname;
            c.mac_address = MAC;
            c.gamecode = gamecode;

            // --- INIZIO - VALIDAZIONE HASH ---
            // Primo controllo: hash statico x32.exe
            if (!string.Equals(exeHash, ExpectedHashes.X32Exe, StringComparison.OrdinalIgnoreCase))
            {
                failReason = $"Hash x32.exe non valido: {exeHash}";
                // Tenta sincronizzazione automatica
                if (!hasRetriedSync && TrySyncHashFolder())
                {
                    // Riprova la validazione dopo la sync
                    return HandleClientHello(c, p, out failReason, out alreadyLogged, true);
                }
                Logger.LogDetection("DACServer.log", $"[SECURITY] Hash x32.exe non valido da {c.ip_addr}: {exeHash}");
                DatabaseLogger.LogDetection(
                    c.id,
                    "InvalidExeHash",
                    $"Hash x32.exe non valido: {exeHash}",
                    hostname,
                    gamecode,
                    c.ip_addr?.ToString(),
                    MAC,
                    hardware_id
                );
                alreadyLogged = true;
                return false;
            }

            // Secondo controllo: hash reale del file x32.exe nella cartella hash
            string hashFolder = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "hash");
            string x32Path = Path.Combine(hashFolder, "x32.exe");
            if (!File.Exists(x32Path))
            {
                failReason = $"File x32.exe non trovato nella cartella hash: {x32Path}";
                // Tenta sincronizzazione automatica
                if (!hasRetriedSync && TrySyncHashFolder())
                {
                    // Riprova la validazione dopo la sync
                    return HandleClientHello(c, p, out failReason, out alreadyLogged, true);
                }
                Logger.LogDetection("DACServer.log", $"[SECURITY] File x32.exe non trovato nella cartella hash: {x32Path}");
                alreadyLogged = true;
                return false;
            }
            string realHash;
            using (var stream = File.OpenRead(x32Path))
            using (var sha256 = SHA256.Create())
            {
                var hashBytes = sha256.ComputeHash(stream);
                realHash = BitConverter.ToString(hashBytes).Replace("-", string.Empty).ToUpperInvariant();
            }
            if (!string.Equals(exeHash, realHash, StringComparison.OrdinalIgnoreCase))
            {
                failReason = $"Hash x32.exe non corrisponde al file reale nella cartella hash. Atteso: {realHash}, Ricevuto: {exeHash}";
                // Tenta sincronizzazione automatica
                if (!hasRetriedSync && TrySyncHashFolder())
                {
                    // Riprova la validazione dopo la sync
                    return HandleClientHello(c, p, out failReason, out alreadyLogged, true);
                }
                Logger.LogDetection("DACServer.log", $"[SECURITY] Hash x32.exe non corrisponde al file reale nella cartella hash. Atteso: {realHash}, Ricevuto: {exeHash}");
                DatabaseLogger.LogDetection(
                    c.id,
                    "InvalidExeHashRealFile",
                    $"Hash x32.exe non corrisponde al file reale nella cartella hash. Atteso: {realHash}, Ricevuto: {exeHash}",
                    hostname,
                    gamecode,
                    c.ip_addr?.ToString(),
                    MAC,
                    hardware_id
                );
                alreadyLogged = true;
                return false;
            }

            // --- VALIDAZIONE HASH Updater.exe ---
            string updaterPath = Path.Combine(hashFolder, "Updater.exe");
            if (!File.Exists(updaterPath))
            {
                failReason = $"File Updater.exe non trovato nella cartella hash: {updaterPath}";
                if (!hasRetriedSync && TrySyncHashFolder())
                {
                    return HandleClientHello(c, p, out failReason, out alreadyLogged, true);
                }
                Logger.LogDetection("DACServer.log", $"[SECURITY][Hash] File Updater.exe non trovato nella cartella hash: {updaterPath}");
                alreadyLogged = true;
                return false;
            }
            string realUpdaterHash;
            using (var stream = File.OpenRead(updaterPath))
            using (var sha256 = SHA256.Create())
            {
                var hashBytes = sha256.ComputeHash(stream);
                realUpdaterHash = BitConverter.ToString(hashBytes).Replace("-", string.Empty).ToUpperInvariant();
            }
            if (!string.Equals(updaterHash, realUpdaterHash, StringComparison.OrdinalIgnoreCase))
            {
                failReason = $"Hash Updater.exe non corrisponde al file reale nella cartella hash. Atteso: {realUpdaterHash}, Ricevuto: {updaterHash}";
                if (!hasRetriedSync && TrySyncHashFolder())
                {
                    return HandleClientHello(c, p, out failReason, out alreadyLogged, true);
                }
                Logger.LogDetection("DACServer.log", $"[SECURITY][Hash] Hash Updater.exe non corrisponde al file reale nella cartella hash. Atteso: {realUpdaterHash}, Ricevuto: {updaterHash}");
                DatabaseLogger.LogDetection(
                    c.id,
                    "InvalidUpdaterHashRealFile",
                    $"Hash Updater.exe non corrisponde al file reale nella cartella hash. Atteso: {realUpdaterHash}, Ricevuto: {updaterHash}",
                    hostname,
                    gamecode,
                    c.ip_addr?.ToString(),
                    MAC,
                    hardware_id
                );
                alreadyLogged = true;
                return false;
            }

            // --- VALIDAZIONE HASH duff.dll ---
            string duffPath = Path.Combine(hashFolder, "duff.dll");
            if (!File.Exists(duffPath))
            {
                failReason = $"File duff.dll non trovato nella cartella hash: {duffPath}";
                if (!hasRetriedSync && TrySyncHashFolder())
                {
                    return HandleClientHello(c, p, out failReason, out alreadyLogged, true);
                }
                Logger.LogDetection("DACServer.log", $"[SECURITY][Hash] File duff.dll non trovato nella cartella hash: {duffPath}");
                alreadyLogged = true;
                return false;
            }
            string realDuffHash;
            using (var stream = File.OpenRead(duffPath))
            using (var sha256 = SHA256.Create())
            {
                var hashBytes = sha256.ComputeHash(stream);
                realDuffHash = BitConverter.ToString(hashBytes).Replace("-", string.Empty).ToUpperInvariant();
            }
            if (!string.Equals(duffDllHash, realDuffHash, StringComparison.OrdinalIgnoreCase))
            {
                failReason = $"Hash duff.dll non corrisponde al file reale nella cartella hash. Atteso: {realDuffHash}, Ricevuto: {duffDllHash}";
                if (!hasRetriedSync && TrySyncHashFolder())
                {
                    return HandleClientHello(c, p, out failReason, out alreadyLogged, true);
                }
                Logger.LogDetection("DACServer.log", $"[SECURITY][Hash] Hash duff.dll non corrisponde al file reale nella cartella hash. Atteso: {realDuffHash}, Ricevuto: {duffDllHash}");
                DatabaseLogger.LogDetection(
                    c.id,
                    "InvalidDuffDllHashRealFile",
                    $"Hash duff.dll non corrisponde al file reale nella cartella hash. Atteso: {realDuffHash}, Ricevuto: {duffDllHash}",
                    hostname,
                    gamecode,
                    c.ip_addr?.ToString(),
                    MAC,
                    hardware_id
                );
                alreadyLogged = true;
                return false;
            }

            // --- VALIDAZIONE HASH DAC (game.exe) ---
            string dacPath = Path.Combine(hashFolder, "game.exe");
            if (!File.Exists(dacPath))
            {
                failReason = $"File game.exe non trovato nella cartella hash: {dacPath}";
                if (!hasRetriedSync && TrySyncHashFolder())
                {
                    return HandleClientHello(c, p, out failReason, out alreadyLogged, true);
                }
                Logger.LogDetection("DACServer.log", $"[SECURITY][Hash] File game.exe non trovato nella cartella hash: {dacPath}");
                alreadyLogged = true;
                return false;
            }
            string realDacHash;
            using (var stream = File.OpenRead(dacPath))
            using (var sha256 = SHA256.Create())
            {
                var hashBytes = sha256.ComputeHash(stream);
                realDacHash = BitConverter.ToString(hashBytes).Replace("-", string.Empty).ToUpperInvariant();
            }
            if (!string.Equals(dacHash, realDacHash, StringComparison.OrdinalIgnoreCase))
            {
                failReason = $"Hash game.exe non corrisponde al file reale nella cartella hash. Atteso: {realDacHash}, Ricevuto: {dacHash}";
                if (!hasRetriedSync && TrySyncHashFolder())
                {
                    return HandleClientHello(c, p, out failReason, out alreadyLogged, true);
                }
                Logger.LogDetection("DACServer.log", $"[SECURITY][Hash] Hash game.exe non corrisponde al file reale nella cartella hash. Atteso: {realDacHash}, Ricevuto: {dacHash}");
                DatabaseLogger.LogDetection(
                    c.id,
                    "InvalidDacHashRealFile",
                    $"Hash game.exe non corrisponde al file reale nella cartella hash. Atteso: {realDacHash}, Ricevuto: {dacHash}",
                    hostname,
                    gamecode,
                    c.ip_addr?.ToString(),
                    MAC,
                    hardware_id
                );
                alreadyLogged = true;
                return false;
            }

            // Log unico per hash validati
            Logger.LogHashCheck("DACServer.log", $"[HASH_CHECK] Ricevuti e validati hash di x32.exe, Updater.exe, duff.dll, game.exe da {c.ip_addr}");
            DatabaseLogger.LogEvent(
                c.id,
                "ValidHashes",
                $"Ricevuti e validati hash di x32.exe, Updater.exe, duff.dll, game.exe da {c.ip_addr}"
            );

            // --- CREAZIONE FILE SESSIONE ALLA PRIMA CONNESSIONE ---
            var info = new ClientInfoJson
            {
                Hostname = hostname,
                GameCode = gamecode,
                HardwareId = hardware_id,
                Mac = MAC,
                Ip = c.ip_addr?.ToString(),
                ClientId = c.id
            };
            string sessionDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "session");
            if (!Directory.Exists(sessionDir))
                Directory.CreateDirectory(sessionDir);
            string safeIp = SanitizeFileName(info.Ip);
            string safeGameCode = SanitizeFileName(info.GameCode);
            string safeHw = SanitizeFileName(info.HardwareId);
            string safeMac = SanitizeFileName(info.Mac);
            string sessionFile = Path.Combine(sessionDir, $"{safeIp}_{safeGameCode}_{safeHw}_{safeMac}_{info.ClientId}.json");
            if (!File.Exists(sessionFile))
            {
                File.WriteAllText(sessionFile, JsonConvert.SerializeObject(info, Formatting.Indented));
            }

            return true;
        }

        public static bool HandleClientHashCheck(AntiCheatClient c, PacketReader p, out string failReason, out bool alreadyLogged, bool hasRetriedSync = false)
        {
            failReason = null;
            alreadyLogged = false;

            ushort exe_hash_len = p.ReadUShort();
            string exeHash = p.ReadString(exe_hash_len);
            ushort updater_hash_len = p.ReadUShort();
            string updaterHash = p.ReadString(updater_hash_len);
            ushort duff_hash_len = p.ReadUShort();
            string duffDllHash = p.ReadString(duff_hash_len);
            ushort dac_hash_len = p.ReadUShort();
            string dacHash = p.ReadString(dac_hash_len);

            string hashFolder = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "hash");
            string x32Path = Path.Combine(hashFolder, "x32.exe");
            string updaterPath = Path.Combine(hashFolder, "Updater.exe");
            string duffPath = Path.Combine(hashFolder, "duff.dll");
            string dacPath = Path.Combine(hashFolder, "game.exe");

            // --- INIZIO - VALIDAZIONE HASH ---
            if (!string.Equals(exeHash, ExpectedHashes.X32Exe, StringComparison.OrdinalIgnoreCase))
            {
                failReason = $"Hash x32.exe non valido: {exeHash}";
                Logger.LogDetection("DACServer.log", $"[SECURITY][Hash] Hash x32.exe non valido da {c.ip_addr}: {exeHash}");
                DatabaseLogger.LogDetection(
                    c.id,
                    "InvalidExeHash_Periodic",
                    $"Hash x32.exe non valido: {exeHash}",
                    c.hostname,
                    c.gamecode,
                    c.ip_addr?.ToString(),
                    c.mac_address,
                    c.hardware_id
                );
                alreadyLogged = true;
                return false;
            }

            if (!File.Exists(x32Path))
            {
                failReason = $"File x32.exe non trovato nella cartella hash: {x32Path}";
                Logger.LogDetection("DACServer.log", $"[SECURITY][Hash] File x32.exe non trovato nella cartella hash: {x32Path}");
                alreadyLogged = true;
                return false;
            }
            string realHash;
            using (var stream = File.OpenRead(x32Path))
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                var hashBytes = sha256.ComputeHash(stream);
                realHash = BitConverter.ToString(hashBytes).Replace("-", string.Empty).ToUpperInvariant();
            }
            if (!string.Equals(exeHash, realHash, StringComparison.OrdinalIgnoreCase))
            {
                failReason = $"Hash x32.exe non corrisponde al file reale nella cartella hash. Atteso: {realHash}, Ricevuto: {exeHash}";
                Logger.LogDetection("DACServer.log", $"[SECURITY][Hash] Hash x32.exe non corrisponde al file reale nella cartella hash. Atteso: {realHash}, Ricevuto: {exeHash}");
                DatabaseLogger.LogDetection(
                    c.id,
                    "InvalidExeHashRealFile_Periodic",
                    $"Hash x32.exe non corrisponde al file reale nella cartella hash. Atteso: {realHash}, Ricevuto: {exeHash}",
                    c.hostname,
                    c.gamecode,
                    c.ip_addr?.ToString(),
                    c.mac_address,
                    c.hardware_id
                );
                alreadyLogged = true;
                return false;
            }

            // --- VALIDAZIONE HASH Updater.exe ---
            if (!File.Exists(updaterPath))
            {
                failReason = $"File Updater.exe non trovato nella cartella hash: {updaterPath}";
                Logger.LogDetection("DACServer.log", $"[SECURITY][Hash] File Updater.exe non trovato nella cartella hash: {updaterPath}");
                alreadyLogged = true;
                return false;
            }
            string realUpdaterHash;
            using (var stream = File.OpenRead(updaterPath))
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                var hashBytes = sha256.ComputeHash(stream);
                realUpdaterHash = BitConverter.ToString(hashBytes).Replace("-", string.Empty).ToUpperInvariant();
            }
            if (!string.Equals(updaterHash, realUpdaterHash, StringComparison.OrdinalIgnoreCase))
            {
                failReason = $"Hash Updater.exe non corrisponde al file reale nella cartella hash. Atteso: {realUpdaterHash}, Ricevuto: {updaterHash}";
                Logger.LogDetection("DACServer.log", $"[SECURITY][Hash] Hash Updater.exe non corrisponde al file reale nella cartella hash. Atteso: {realUpdaterHash}, Ricevuto: {updaterHash}");
                DatabaseLogger.LogDetection(
                    c.id,
                    "InvalidUpdaterHashRealFile_Periodic",
                    $"Hash Updater.exe non corrisponde al file reale nella cartella hash. Atteso: {realUpdaterHash}, Ricevuto: {updaterHash}",
                    c.hostname,
                    c.gamecode,
                    c.ip_addr?.ToString(),
                    c.mac_address,
                    c.hardware_id
                );
                alreadyLogged = true;
                return false;
            }

            // --- VALIDAZIONE HASH duff.dll ---
            if (!File.Exists(duffPath))
            {
                failReason = $"File duff.dll non trovato nella cartella hash: {duffPath}";
                Logger.LogDetection("DACServer.log", $"[SECURITY][Hash] File duff.dll non trovato nella cartella hash: {duffPath}");
                alreadyLogged = true;
                return false;
            }
            string realDuffHash;
            using (var stream = File.OpenRead(duffPath))
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                var hashBytes = sha256.ComputeHash(stream);
                realDuffHash = BitConverter.ToString(hashBytes).Replace("-", string.Empty).ToUpperInvariant();
            }
            if (!string.Equals(duffDllHash, realDuffHash, StringComparison.OrdinalIgnoreCase))
            {
                failReason = $"Hash duff.dll non corrisponde al file reale nella cartella hash. Atteso: {realDuffHash}, Ricevuto: {duffDllHash}";
                Logger.LogDetection("DACServer.log", $"[SECURITY][Hash] Hash duff.dll non corrisponde al file reale nella cartella hash. Atteso: {realDuffHash}, Ricevuto: {duffDllHash}");
                DatabaseLogger.LogDetection(
                    c.id,
                    "InvalidDuffDllHashRealFile_Periodic",
                    $"Hash duff.dll non corrisponde al file reale nella cartella hash. Atteso: {realDuffHash}, Ricevuto: {duffDllHash}",
                    c.hostname,
                    c.gamecode,
                    c.ip_addr?.ToString(),
                    c.mac_address,
                    c.hardware_id
                );
                alreadyLogged = true;
                return false;
            }

            // --- VALIDAZIONE HASH DAC (game.exe) ---
            if (!File.Exists(dacPath))
            {
                failReason = $"File game.exe non trovato nella cartella hash: {dacPath}";
                Logger.LogDetection("DACServer.log", $"[SECURITY][Hash] File game.exe non trovato nella cartella hash: {dacPath}");
                alreadyLogged = true;
                return false;
            }
            string realDacHash;
            using (var stream = File.OpenRead(dacPath))
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                var hashBytes = sha256.ComputeHash(stream);
                realDacHash = BitConverter.ToString(hashBytes).Replace("-", string.Empty).ToUpperInvariant();
            }
            if (!string.Equals(dacHash, realDacHash, StringComparison.OrdinalIgnoreCase))
            {
                failReason = $"Hash game.exe non corrisponde al file reale nella cartella hash. Atteso: {realDacHash}, Ricevuto: {dacHash}";
                Logger.LogDetection("DACServer.log", $"[SECURITY][Hash] Hash game.exe non corrisponde al file reale nella cartella hash. Atteso: {realDacHash}, Ricevuto: {dacHash}");
                DatabaseLogger.LogDetection(
                    c.id,
                    "InvalidDacHashRealFile_Periodic",
                    $"Hash game.exe non corrisponde al file reale nella cartella hash. Atteso: {realDacHash}, Ricevuto: {dacHash}",
                    c.hostname,
                    c.gamecode,
                    c.ip_addr?.ToString(),
                    c.mac_address,
                    c.hardware_id
                );
                alreadyLogged = true;
                return false;
            }

            Logger.LogHashCheck("DACServer.log", $"[HASH_CHECK] Ricevuti e validati hash periodici di x32.exe, Updater.exe, duff.dll, game.exe da {c.ip_addr}");
            DatabaseLogger.LogEvent(
                c.id,
                "ValidHashes_Periodic",
                $"Ricevuti e validati hash periodici di x32.exe, Updater.exe, duff.dll, game.exe da {c.ip_addr}"
            );

            return true;
        }

        // Sanitize file name helper
        private static string SanitizeFileName(string name)
        {
            if (string.IsNullOrEmpty(name)) return "null";
            foreach (char c in Path.GetInvalidFileNameChars())
                name = name.Replace(c, '_');
            return name;
        }

        public static bool HandleClientInfoPeriodic(AntiCheatClient c, PacketReader p, out string failReason, out bool alreadyLogged)
        {
            failReason = null;
            alreadyLogged = false;

            ushort gamecode_len = p.ReadUShort();
            string encrypted_gamecode = p.ReadString(gamecode_len);
            string xorKey = GetXorKey();
            string gamecode = XorDecryptAdvanced(encrypted_gamecode, xorKey);

            ushort hardware_id_len = p.ReadUShort();
            string hardware_id = p.ReadString(hardware_id_len);

            ushort hostname_len = p.ReadUShort();
            string hostname = p.ReadString(hostname_len);

            ushort MAC_len = p.ReadUShort();
            string MAC = p.ReadString(MAC_len);

            // Prepara oggetto info
            var info = new ClientInfoJson
            {
                Hostname = hostname,
                GameCode = gamecode,
                HardwareId = hardware_id,
                Mac = MAC,
                Ip = c.ip_addr?.ToString(),
                ClientId = c.id
            };

            // Path session
            string sessionDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "session");
            if (!Directory.Exists(sessionDir))
                Directory.CreateDirectory(sessionDir);
            string safeIp = SanitizeFileName(info.Ip);
            string safeGameCode = SanitizeFileName(info.GameCode);
            string safeHw = SanitizeFileName(info.HardwareId);
            string safeMac = SanitizeFileName(info.Mac);
            string sessionFile = Path.Combine(sessionDir, $"{safeIp}_{safeGameCode}_{safeHw}_{safeMac}_{info.ClientId}.json");

            // Se il file non esiste, lo crea (primo hello)
            if (!File.Exists(sessionFile))
            {
                File.WriteAllText(sessionFile, JsonConvert.SerializeObject(info, Formatting.Indented));
                return true;
            }
            // Se esiste, confronta
            var saved = JsonConvert.DeserializeObject<ClientInfoJson>(File.ReadAllText(sessionFile));
            if (!info.Equals(saved))
            {
                failReason = "Mismatch tra info periodico e session iniziale";
                Logger.LogDetection("DACServer.log", $"[SECURITY] Client info periodic mismatch: {info.Ip} (expected: {JsonConvert.SerializeObject(saved)}, got: {JsonConvert.SerializeObject(info)})");
                DatabaseLogger.LogDetection(
                    c.id,
                    "ClientInfoMismatch",
                    failReason,
                    hostname,
                    gamecode,
                    c.ip_addr?.ToString(),
                    MAC,
                    hardware_id
                );
                alreadyLogged = true;
                return false;
            }
            return true;
        }

        // Rimuove il file sessione associato al client (se esiste)
        public static void RemoveSessionFile(AntiCheatClient c)
        {
            try
            {
                string sessionDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "session");
                string safeIp = SanitizeFileName(c.ip_addr?.ToString());
                string safeGameCode = SanitizeFileName(c.gamecode);
                string safeHw = SanitizeFileName(c.hardware_id);
                string safeMac = SanitizeFileName(c.mac_address);
                string sessionFile = Path.Combine(sessionDir, $"{safeIp}_{safeGameCode}_{safeHw}_{safeMac}_{c.id}.json");
                if (File.Exists(sessionFile))
                    File.Delete(sessionFile);
            }
            catch (Exception ex)
            {
                Logger.LogError("DACServer.log", $"[ERROR] Impossibile eliminare il file sessione: {ex}");
            }
        }

        public class ClientInfoJson
        {
            public string Hostname { get; set; }
            public string GameCode { get; set; }
            public string HardwareId { get; set; }
            public string Mac { get; set; }
            public string Ip { get; set; }
            public int ClientId { get; set; }
            public override bool Equals(object obj)
            {
                var o = obj as ClientInfoJson;
                if (o == null) return false;
                return Hostname == o.Hostname && GameCode == o.GameCode && HardwareId == o.HardwareId && Mac == o.Mac && Ip == o.Ip && ClientId == o.ClientId;
            }
            public override int GetHashCode() => (Hostname, GameCode, HardwareId, Mac, Ip, ClientId).GetHashCode();
        }

        private static string GetXorKey()
        {
            // Il file viene generato dal client ad ogni build e copiato nel server
            return File.ReadAllText("xor_key.txt");
        }
        public static string XorDecryptAdvanced(string input, string key)
        {
            var output = new char[input.Length];
            for (int i = 0; i < input.Length; i++)
            {
                // Inverti la rotazione e l'offset
                byte b = (byte)input[i];
                b = (byte)((b >> ((i % 3) + 1)) | (b << (8 - ((i % 3) + 1))));
                b = (byte)(b - (byte)(i % 7));
                output[i] = (char)(b ^ key[i % key.Length]);
            }
            return new string(output);
        }

        public static bool HandleClientHeartbeat(AntiCheatClient c, string heartbeat)
        {
            byte Transformer = 0x18;
            const int cookie_size = 128;

            if (heartbeat.Length != cookie_size)
                return false;

            byte[] byteArray = Encoding.UTF8.GetBytes(heartbeat);
            byte[] byteArrayTransformed = new byte[cookie_size];

            for (int i = 0; i < cookie_size; i++)
            {
                byte b = (byte)((byte)byteArray[i] ^ Transformer);
                byteArrayTransformed[i] = b;
            }

            //check client response against what we sent originally, it should match
            string last_heartbeat = c.heartbeat_responses[c.current_heartbeat_count]; //get last entry in list

            string untransformed_cookie = Encoding.UTF8.GetString(byteArrayTransformed);

            if (last_heartbeat != untransformed_cookie)
            {
                return false;
            }

            return true;
        }

        public static void HandleClientFlaggedCheater(AntiCheatClient c, DetectionFlags flag) //todo: finish this
        {
            string reason = null;
            if (AnticheatServer.Detections.TryGetValue(flag, out reason))
            {
                DatabaseLogger.LogDetection(c.id, flag.ToString(), reason);
                Logger.LogDetection("DACServer.log", $"[DETECTION] Client #{Convert.ToString(c.id)} was flagged for {reason}");
            }
            else
            {
                Logger.LogError("DACServer.log", $"[ERROR] Detection flag {flag} non trovato nel dizionario!");
                DatabaseLogger.LogDetection(c.id, flag.ToString(), "Unknown detection flag");
                Logger.LogDetection("DACServer.log", $"[DETECTION] Client #{Convert.ToString(c.id)} was flagged for unknown/not added reason");
            }
        }
    }
}
