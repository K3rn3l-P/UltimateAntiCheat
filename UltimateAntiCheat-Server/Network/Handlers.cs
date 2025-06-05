//UltimateAnticheat Server - By AlSch092 @ Github

using System;
using System.Text;
using System.IO;
using System.Security.Cryptography;

namespace UACServer.Network
{
    internal class Handlers
    {
        public static bool HandleClientHello(AntiCheatClient c, PacketReader p, out string failReason, out bool alreadyLogged) //hardwareID, hostname, MAC addr as fields
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
                Logger.Log("DACServer.log", $"[SECURITY] Hash x32.exe non valido da {c.ip_addr}: {exeHash}");
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
                Logger.Log("DACServer.log", $"[SECURITY] File x32.exe non trovato nella cartella hash: {x32Path}");
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
                Logger.Log("DACServer.log", $"[SECURITY] Hash x32.exe non corrisponde al file reale nella cartella hash. Atteso: {realHash}, Ricevuto: {exeHash}");
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
                Logger.Log("DACServer.log", $"[SECURITY] File Updater.exe non trovato nella cartella hash: {updaterPath}");
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
                Logger.Log("DACServer.log", $"[SECURITY] Hash Updater.exe non corrisponde al file reale nella cartella hash. Atteso: {realUpdaterHash}, Ricevuto: {updaterHash}");
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
                Logger.Log("DACServer.log", $"[SECURITY] File duff.dll non trovato nella cartella hash: {duffPath}");
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
                Logger.Log("DACServer.log", $"[SECURITY] Hash duff.dll non corrisponde al file reale nella cartella hash. Atteso: {realDuffHash}, Ricevuto: {duffDllHash}");
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
                Logger.Log("DACServer.log", $"[SECURITY] File game.exe non trovato nella cartella hash: {dacPath}");
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
                Logger.Log("DACServer.log", $"[SECURITY] Hash game.exe non corrisponde al file reale nella cartella hash. Atteso: {realDacHash}, Ricevuto: {dacHash}");
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
            Logger.Log("DACServer.log", $"[SECURITY] Ricevuti e validati hash di x32.exe, Updater.exe, duff.dll, game.exe da {c.ip_addr}");
            DatabaseLogger.LogEvent(
                c.id,
                "ValidHashes",
                $"Ricevuti e validati hash di x32.exe, Updater.exe, duff.dll, game.exe da {c.ip_addr}"
            );

            return true;
        }
        // --- FINE - VALIDAZIONE HASH ---

        public static bool HandleClientHashCheck(AntiCheatClient c, PacketReader p, out string failReason, out bool alreadyLogged)
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
                Logger.Log("DACServer.log", $"[HASH_CHECK] Hash x32.exe non valido da {c.ip_addr}: {exeHash}");
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
                Logger.Log("DACServer.log", $"[HASH_CHECK] File x32.exe non trovato nella cartella hash: {x32Path}");
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
                Logger.Log("DACServer.log", $"[HASH_CHECK] Hash x32.exe non corrisponde al file reale nella cartella hash. Atteso: {realHash}, Ricevuto: {exeHash}");
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
                Logger.Log("DACServer.log", $"[HASH_CHECK] File Updater.exe non trovato nella cartella hash: {updaterPath}");
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
                Logger.Log("DACServer.log", $"[HASH_CHECK] Hash Updater.exe non corrisponde al file reale nella cartella hash. Atteso: {realUpdaterHash}, Ricevuto: {updaterHash}");
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
                Logger.Log("DACServer.log", $"[HASH_CHECK] File duff.dll non trovato nella cartella hash: {duffPath}");
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
                Logger.Log("DACServer.log", $"[HASH_CHECK] Hash duff.dll non corrisponde al file reale nella cartella hash. Atteso: {realDuffHash}, Ricevuto: {duffDllHash}");
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
                Logger.Log("DACServer.log", $"[HASH_CHECK] File game.exe non trovato nella cartella hash: {dacPath}");
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
                Logger.Log("DACServer.log", $"[HASH_CHECK] Hash game.exe non corrisponde al file reale nella cartella hash. Atteso: {realDacHash}, Ricevuto: {dacHash}");
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

            Logger.Log("DACServer.log", $"[HASH_CHECK] Ricevuti e validati hash periodici di x32.exe, Updater.exe, duff.dll, game.exe da {c.ip_addr}");
            DatabaseLogger.LogEvent(
                c.id,
                "ValidHashes_Periodic",
                $"Ricevuti e validati hash periodici di x32.exe, Updater.exe, duff.dll, game.exe da {c.ip_addr}"
            );

            return true;
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
                Logger.Log("DACServer.log", $"[DETECTION] Client #{Convert.ToString(c.id)} was flagged for {reason}");
            }
            else
            {
                Logger.Log("DACServer.log", $"[ERROR] Detection flag {flag} non trovato nel dizionario!");
                DatabaseLogger.LogDetection(c.id, flag.ToString(), "Unknown detection flag");
                Logger.Log("DACServer.log", $"[DETECTION] Client #{Convert.ToString(c.id)} was flagged for unknown/not added reason");
            }
        }
    }
}
