//UltimateAnticheat Server - By AlSch092 @ Github

using System;
using System.Text;
using System.IO;

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

            if (hardware_id_len == 0 || hostname_len == 0 || MAC_len == 0 || hash_len == 0)
            {
                failReason = "Uno o più campi obbligatori sono vuoti";
                return false;
            }

            c.hardware_id = hardware_id;
            c.hostname = hostname;
            c.mac_address = MAC;
            c.gamecode = gamecode;

            // --- VALIDAZIONE HASH ---
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

            // Log hash valido
            Logger.Log("DACServer.log", $"[SECURITY] Hash x32.exe valido da {c.ip_addr}: {exeHash}");
            DatabaseLogger.LogEvent(c.id, "ValidExeHash", $"Hash x32.exe valido: {exeHash}");

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
