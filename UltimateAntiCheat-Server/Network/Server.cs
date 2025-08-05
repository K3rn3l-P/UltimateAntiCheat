//UltimateAnticheat Server - By AlSch092 @ Github
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Collections.Concurrent; // Aggiungi questa riga
using System.Linq;
using UACServer.Network.Opcodes;
using Newtonsoft.Json;
using UACServer.Network; // <-- aggiunto per BlacklistManager

namespace UACServer.Network
{
    public class SessionInfo
    {
        public string HardwareId { get; set; }
        public string Mac { get; set; }
        public string GameCode { get; set; }
        public int ClientId { get; set; }
        public string Hostname { get; set; }
        public override bool Equals(object obj)
        {
            var o = obj as SessionInfo;
            if (o == null) return false;
            return HardwareId == o.HardwareId && Mac == o.Mac && GameCode == o.GameCode && ClientId == o.ClientId;
        }
        public override int GetHashCode() => (HardwareId, Mac, GameCode, ClientId).GetHashCode();
    }

    class AnticheatServer
    {
        // --- Parametri di configurazione principali ---
        // Versione del protocollo/server
        private const short versionNum = 100;
        // Intervallo tra i messaggi di heartbeat inviati al client (in millisecondi)
        private const int heartbeatDelay = 60000; // 1 minuto
        // Intervallo tra i controlli periodici degli hash (in millisecondi)
        // In sintesi: ogni quanto il server controlla lo stato dei client.
        private const int checkIntervalMs = 60000; // 1 minuto
        // Tempo massimo consentito senza ricevere un hash check periodico dal client (in minuti)
        // In sintesi: quanto tempo può passare senza ricevere hash check da un client prima di prendere provvedimenti.
        private const int maxHashCheckDelayMinutes = 35; // tempo massimo senza hash check
        // Tempo massimo consentito senza ricevere info periodiche dal client (in minuti)
        private const int maxInfoCheckDelayMinutes = 15; // tempo massimo senza info check
        // Timeout per la ricezione del primo pacchetto dal client (in millisecondi)
        private const int readTimeoutMs = 5000; // 5 secondi

        private TcpListener listener;
        private List<AntiCheatClient> clients = new List<AntiCheatClient>();
        private readonly object clientsLock = new object();
        private bool isRunning = false;
        public static ConcurrentDictionary<string, List<SessionInfo>> AuthenticatedSessions = new ConcurrentDictionary<string, List<SessionInfo>>();
        public static Dictionary<DetectionFlags, string> Detections = new Dictionary<DetectionFlags, string>();

        public AnticheatServer()
        {
            AddDetectionDictionary();
            BlacklistManager.Start();
        }

        public void Start(string ipAddress, int port)
        {
            listener = new TcpListener(IPAddress.Parse(ipAddress), port);
            listener.Start();
            isRunning = true;

            Logger.Log("DACServer.log", "[INFO] Server started. Listening for connections...");
            listener.BeginAcceptTcpClient(HandleClientConnected, null); //listen for client connections asynchronously

            // Avvia il thread di controllo hash periodico
            Thread hashCheckMonitor = new Thread(() => MonitorPeriodicHashChecks());
            hashCheckMonitor.IsBackground = true;
            hashCheckMonitor.Start();
        }

        private void AddDetectionDictionary()
        {
            //general Detections
            Detections.Add(DetectionFlags.PAGE_PROTECTIONS, "Page protections are not as expected");
            Detections.Add(DetectionFlags.CODE_INTEGRITY, "Code integrity check failed");
            Detections.Add(DetectionFlags.DLL_TAMPERING, "DLL tampering detected");
            Detections.Add(DetectionFlags.BAD_IAT, "Invalid IAT detected");
            Detections.Add(DetectionFlags.OPEN_PROCESS_HANDLES, "Unexpected open process handles detected");
            Detections.Add(DetectionFlags.UNSIGNED_DRIVERS, "Unsigned drivers detected");
            Detections.Add(DetectionFlags.INJECTED_ILLEGAL_PROGRAM, "Injected illegal program detected");
            Detections.Add(DetectionFlags.EXTERNAL_ILLEGAL_PROGRAM, "External illegal program detected");
            Detections.Add(DetectionFlags.HYPERVISOR, "Hypervisor detected");
            Detections.Add(DetectionFlags.REGISTRY_KEY_MODIFICATIONS, "Registry key modifications detected");

            //debug-related Detections
            Detections.Add(DetectionFlags.DEBUG_WINAPI_DEBUGGER, "WinAPI debugger detected");
            Detections.Add(DetectionFlags.DEBUG_PEB, "PEB (Process Environment Block) debugger detected");
            Detections.Add(DetectionFlags.DEBUG_HARDWARE_REGISTERS, "Hardware register debugger detected");
            Detections.Add(DetectionFlags.DEBUG_HEAP_FLAG, "Heap flag debugger detected");
            Detections.Add(DetectionFlags.DEBUG_INT3, "INT3 breakpoint detected");
            Detections.Add(DetectionFlags.DEBUG_INT2C, "INT2C breakpoint detected");
            Detections.Add(DetectionFlags.DEBUG_CLOSEHANDLE, "CloseHandle debugger detected");
            Detections.Add(DetectionFlags.DEBUG_DEBUG_OBJECT, "Debug object detected");
            Detections.Add(DetectionFlags.DEBUG_VEH_DEBUGGER, "VEH (Vector Exception Handler) debugger detected");
            Detections.Add(DetectionFlags.DEBUG_KERNEL_DEBUGGER, "Kernel debugger detected");
            Detections.Add(DetectionFlags.DEBUG_TRAP_FLAG, "Trap flag debugger detected");
            Detections.Add(DetectionFlags.DEBUG_DEBUG_PORT, "Debug port detected");
            Detections.Add(DetectionFlags.DEBUG_PROCESS_DEBUG_FLAGS, "Process debug flags detected");
            Detections.Add(DetectionFlags.DEBUG_REMOTE_DEBUGGER, "Remote debugger detected");
            Detections.Add(DetectionFlags.DEBUG_DBG_BREAK, "Debug break detected");
        }

        private void HandleClientConnected(IAsyncResult result)
        {
            if (!isRunning)
                return;

            UACServer.Network.DatabaseLogger.CleanupOldLogs();

            TcpClient client = listener.EndAcceptTcpClient(result);
            string ip = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();

            if (DatabaseLogger.IsIpBanned(ip))
            {
                Logger.LogDetection("DACServer.log", $"[SECURITY][SERVER][BLOCKED] Connessione rifiutata: IP {ip} bannato (Status = -5)");
                DatabaseLogger.LogDetection(
                    0,
                    "ServerBlockedBanned",
                    $"[SERVER][BLOCKED] Connessione rifiutata: IP {ip} bannato (Status = -5)",
                    null,
                    null,
                    ip,
                    null,
                    null
                );
                client.Close();
                client.Dispose();
                listener.BeginAcceptTcpClient(HandleClientConnected, null);
                return;
            }

            Logger.Log("DACServer.log", $"Client connected: {((IPEndPoint)client.Client.RemoteEndPoint).Address}");

            // Rimuovi anche la sessione autenticata e il file sessione per IP
            List<SessionInfo> removedSessions;
            if (AuthenticatedSessions.TryRemove(ip, out removedSessions))
            {
                Logger.LogAuth("DACServer.log", $"[AUTH] Session forcibly removed for {ip} (sessions: {removedSessions?.Count ?? 0}) due to new connection.");
                if (removedSessions != null)
                {
                    foreach (var sess in removedSessions)
                    {
                        var dummyClient = new AntiCheatClient { ip_addr = IPAddress.Parse(ip), gamecode = sess.GameCode, hardware_id = sess.HardwareId, mac_address = sess.Mac, id = sess.ClientId };
                        Handlers.RemoveSessionFile(dummyClient);
                        Logger.LogAuth("DACServer.log", $"[AUTH] Session file forcibly removed for {ip} (gamecode: {sess.GameCode}) due to new connection.");
                    }
                }
            }

            AntiCheatClient c = new AntiCheatClient();
            c.id = new Random().Next(0, int.MaxValue);
            c.net_client = client;
            c.ip_addr = ((IPEndPoint)client.Client.RemoteEndPoint).Address;
            c.connected_at = Environment.TickCount;
            lock (clientsLock)
            {
                clients.Add(c);
            }

            byte[] buffer = new byte[1024];
            var stream = client.GetStream();
            stream.ReadTimeout = readTimeoutMs;

            try
            {
                client.GetStream().BeginRead(buffer, 0, buffer.Length, HandleMessageReceived, new object[] { client, buffer });
            }
            catch (IOException ex)
            {
                Logger.LogError("DACServer.log", "[ERROR] Failed to read client data @ HandleClientConnected");
                return;
            }

            listener.BeginAcceptTcpClient(HandleClientConnected, null);
        }

        private void HandleMessageReceived(IAsyncResult result)
        {
            try
            {
                if (!isRunning)
                    return;

                object[] asyncState = (object[])result.AsyncState;
                TcpClient client = (TcpClient)asyncState[0];
                byte[] buffer = (byte[])asyncState[1];

                // TROVA IL CLIENT PRIMA DEL TRY/CATCH
                AntiCheatClient c = null;
                foreach (AntiCheatClient ca in clients)
                {
                    if (ca.net_client == client)
                    {
                        c = ca;
                        break;
                    }
                }

                // --- FIX: Check if client is disposed, not connected, o disconnesso graceful ---
                if (c == null || c.net_client == null || !c.net_client.Connected || c.gracefulDisconnect)
                {
                    // Rimuovi dalla lista se non già rimosso
                    lock (clientsLock)
                    {
                        clients.Remove(c);
                    }
                    try { client.Close(); } catch { }
                    // If gracefulDisconnect, do not log error or remove session again
                    return;
                }

                int bytesRead = 0;

                try
                {
                    bytesRead = client.GetStream().EndRead(result);
                }
                catch (IOException ex)
                {
                    Logger.LogError("DACServer.log", "[ERROR] IOExcpetion @ HandleMessageReceived(): " + ex.Message);
                    Logger.LogDetection("DACServer.log", $"[SECURITY] Connessione chiusa per timeout o errore IO: {ex.Message}");
                    Console.WriteLine("Removing client from list");

                    if (c != null)
                    {
                        DatabaseLogger.LogDetection(
                            c.id,
                            "ForcedDisconnect",
                            $"Connection forcibly closed or IO error: {ex.Message}",
                            c.hostname,
                            c.gamecode,
                            c.ip_addr?.ToString(),
                            c.mac_address,
                            c.hardware_id
                        );
                        DatabaseLogger.LogLogoutEvent(c.id, DateTime.Now);
                        RemoveAuthenticatedSession(c);
                        Handlers.RemoveSessionFile(c);
                    }

                    lock (clientsLock)
                    {
                        clients.Remove(c);
                    }
                    return;
                }
                catch (ObjectDisposedException ex)
                {
                    Logger.LogDetection("DACServer.log", "[SECURITY] ObjectDisposedException @ HandleMessageReceived(): " + ex.Message);
                    return;
                }

                foreach (AntiCheatClient ca in clients)
                {
                    if (ca.net_client == client) //need this for HandlePacket
                        c = ca;
                }

                if (bytesRead > 0)
                {
                    bool alreadyLogged;
                    if (!HandlePacket(c, buffer, bytesRead, out alreadyLogged))
                    {
                        // Do not log error or remove session if gracefulDisconnect is set
                        if (c != null && c.gracefulDisconnect)
                        {
                            return;
                        }
                        Logger.LogHeartbeat("DACServer.log", "[HEARTBEAT] Client heartbeat was incorrect, disconnecting client " + c?.hardware_id);
                        if (!alreadyLogged && (c == null || !c.gracefulDisconnect))
                        {
                            DatabaseLogger.LogDetection(
                                c?.id ?? 0,
                                "InvalidPacket",
                                "Client sent an invalid or malformed packet (possible signature error)",
                                c?.hostname,
                                c?.gamecode,
                                c?.ip_addr?.ToString(),
                                c?.mac_address,
                                c?.hardware_id
                            );
                        }
                        RemoveAuthenticatedSession(c);
                        Handlers.RemoveSessionFile(c);
                        try
                        {
                            if (c?.net_client?.Client != null && c.net_client.Client.Connected)
                                c.net_client.Client.Disconnect(false);
                        }
                        catch (ObjectDisposedException) { }
                        c?.net_client?.Dispose();
                        return;
                    }

                    if (!c.in_heartbeat_loop)
                    {
                        c.in_heartbeat_loop = true;

                        // Send something to client every 60 seconds after receiving the first piece of data
                        ThreadPool.QueueUserWorkItem(state => //...not the best C# code by any means
                        {
                            var clientState = (object[])state;
                            var clientToSend = (TcpClient)clientState[0];

                            Thread.Sleep(heartbeatDelay);

                            if (clientToSend.Connected)
                            {
                                Console.WriteLine("Sending heartbeat...");
                                if (!SendHeartbeat(c))
                                {
                                    clientToSend.Client.Disconnect(false);
                                    return;
                                }
                                else
                                {
                                    c.in_heartbeat_loop = false;
                                }
                            }
                            else
                            {
                                return;
                            }

                        }, asyncState);
                    }

                    try
                    {
                        client.GetStream().BeginRead(buffer, 0, buffer.Length, HandleMessageReceived, asyncState);
                    }
                    catch (IOException ex)
                    {
                        Logger.LogError("DACServer.log", "[ERROR] Failed to read client data @ HandleMessageReceived");
                        return;
                    }
                    catch (ObjectDisposedException ex)
                    {
                        Logger.LogDetection("DACServer.log", "[SECURITY] ObjectDisposedException @ BeginRead in HandleMessageReceived: " + ex.Message);
                        return;
                    }
                }
                else
                {
                    // Nel blocco else (bytesRead <= 0)
                    string ip = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();
                    RemoveAuthenticatedSession(c);
                    Handlers.RemoveSessionFile(c);
                    Logger.LogDetection("DACServer.log", $"[SECURITY] Client {((IPEndPoint)client.Client.RemoteEndPoint).Address} disconnected (possibly due to invalid signature or malformed packet).");

                    // INVIA MESSAGGIO DI ERRORE AL CLIENT PRIMA DI CHIUDERE
                    if (c != null)
                    {
                        SendErrorAndClose(c, "An unexpected error occurred. Please contact support.");
                    }

                    AntiCheatClient toRemove = null;
                    foreach (AntiCheatClient ca in clients)
                    {
                        if (ca.net_client == client)
                            toRemove = ca;
                    }

                    if (toRemove != null)
                    {
                        if (toRemove.gracefulDisconnect)
                        {
                            Logger.LogInfoTag("DACServer.log", $"Client {ip} disconnected gracefully.");
                            DatabaseLogger.LogLogoutEvent(toRemove.id, DateTime.Now);
                        }
                        else
                        {
                            Logger.LogDetection("DACServer.log", $"[SECURITY] Client {ip} disconnected (possibly due to invalid signature or malformed packet).");
                            DatabaseLogger.LogDetection(
                                toRemove.id,
                                "ClientDisconnected",
                                "Disconnected unexpectedly (possible invalid signature or malformed packet)",
                                toRemove.hostname,
                                toRemove.gamecode,
                                ip,
                                toRemove.mac_address,
                                toRemove.hardware_id
                            );
                            DatabaseLogger.LogLogoutEvent(toRemove.id, DateTime.Now);
                        }
                        RemoveAuthenticatedSession(toRemove);
                        Handlers.RemoveSessionFile(toRemove);
                        try
                        {
                            if (toRemove?.net_client?.Client != null && toRemove.net_client.Client.Connected)
                                toRemove.net_client.Client.Disconnect(false);
                        }
                        catch (ObjectDisposedException) { }
                        toRemove?.net_client?.Dispose();
                        clients.Remove(toRemove);
                    }

                    client.Close();
                }

            }
            catch (Exception ex)
            {
                Logger.LogError("DACServer.log", "[ERROR] Exception in HandleMessageReceived: " + ex.ToString());
            }
        }

        private bool SendBytes(AntiCheatClient c, PacketWriter p)
        {
            if (!c.net_client.Client.Connected)
                return false;

            byte[] buffer = p.m_stream.GetBuffer();

            Cipher(buffer, buffer.Length);

            if (c.net_client.Connected)
            {
                c.net_client.GetStream().Write(buffer, 0, buffer.Length);
                return true;
            }

            return false;
        }


        private bool SendClientHello(AntiCheatClient c)
        {
            PacketWriter p = Factory.ClientHello(versionNum);
            return SendBytes(c, p);
        }

        private bool SendHeartbeat(AntiCheatClient c)
        {
            string cookie = RandomStringGenerator.GenerateRandomString(128);
            PacketWriter p = Factory.MakeHeartbeat(cookie);
            c.heartbeat_responses.Add(cookie); //save heartbeats so that we can compare client responses to them fpr .
            return SendBytes(c, p);
        }

        private void Cipher(byte[] buffer, int length)
        {
            const byte xorKey = 0x90;
            const byte operationKey = 0x14;

            for (int i = 0; i < length; i++)
            {
                if (i % 2 == 0)
                    buffer[i] = (byte)((buffer[i] - operationKey) ^ xorKey);
                else
                    buffer[i] = (byte)((buffer[i] + operationKey) ^ xorKey);
            }
        }

        private bool HandlePacket(AntiCheatClient c, byte[] buffer, int length, out bool alreadyLogged)
        {
            alreadyLogged = false;
            try
            {
                if (buffer == null || length == 0)
                    return false;

                Cipher(buffer, length);

                PacketReader p = new PacketReader(buffer);
                ushort opcode = p.ReadUShort();

                switch ((Opcodes.CS)opcode)
                {
                    case Opcodes.CS.CS_HELLO: //client hello
                        {
                            string failReason;
                            bool alreadyLoggedHello;
                            if (!Handlers.HandleClientHello(c, p, out failReason, out alreadyLoggedHello, false))
                            {
                                Logger.LogError("DACServer.log", $"[ERROR] Client hello transaction failed: {failReason}");
                                if (!alreadyLoggedHello)
                                {
                                    DatabaseLogger.LogDetection(
                                        c?.id ?? 0,
                                        "InvalidHello",
                                        failReason ?? "Client hello failed for unknown reason",
                                        c?.hostname,
                                        c?.gamecode,
                                        c?.ip_addr?.ToString(),
                                        c?.mac_address,
                                        c?.hardware_id
                                    );
                                }
                                alreadyLogged = true;
                                return SendErrorAndClose(c, "A security issue was detected. Please restart the game.");
                            }
                            else
                            {
                                Logger.Log("DACServer.log", $"Client info: Hostname={c.hostname}, GameCode={c.gamecode}, ID={c.id}, IP={c.ip_addr}");
                                // --- LOGICA MULTISESSIONE PER IP ---
                                var session = new SessionInfo {
                                    HardwareId = c.hardware_id,
                                    Mac = c.mac_address,
                                    GameCode = c.gamecode,
                                    ClientId = c.id,
                                    Hostname = c.hostname
                                };
                                var ip = c.ip_addr.ToString();
                                bool sessionLimitReached = false;
                                AuthenticatedSessions.AddOrUpdate(ip,
                                    key => new List<SessionInfo> { session },
                                    (key, list) => {
                                        if (list.Any(s => s.Equals(session)))
                                            return list;
                                        if (list.Count >= 2)
                                        {
                                            sessionLimitReached = true;
                                            return list;
                                        }
                                        list.Add(session);
                                        return list;
                                    });
                                if (sessionLimitReached)
                                {
                                    SendErrorAndClose(c, "Maximum number of clients from this IP reached.");
                                    alreadyLogged = true;
                                    return false;
                                }
                                DatabaseLogger.LogClientInfo(
                                    c.hostname,
                                    c.gamecode,
                                    c.id,
                                    c.ip_addr?.ToString(),
                                    c.mac_address,
                                    c.hardware_id,
                                    "Client info"
                                );
                                DatabaseLogger.LogLoginEvent(
                                    c.id,
                                    c.hostname,
                                    DateTime.Now,
                                    c.ip_addr?.ToString()
                                );
                            }
                            if (!SendClientHello(c))
                            {
                                Logger.LogError("DACServer.log", "[ERROR] Client hello transaction failed: failure sending bytes to client");
                                return false;
                            }
                        }
                        break;
                    case Opcodes.CS.CS_HEARTBEAT:
                        {
                            short cookie_len = p.ReadShort();
                            string cookie_str = p.ReadString(128);

                            if (!Handlers.HandleClientHeartbeat(c, cookie_str))
                            {
                                Logger.LogHeartbeat("DACServer.log", "[HEARTBEAT] Client heartbeat transaction failed: client heartbeat cookie was incorrect.");
                                DatabaseLogger.LogEvent(c.id, "HeartbeatFailed", "Heartbeat cookie mismatch");
                                return SendErrorAndClose(c, "An unexpected error occurred. Please contact support.");
                            }
                            else
                            {
                                var now = DateTime.UtcNow.Date;
                                if (c.LastHeartbeatLog == null || c.LastHeartbeatLog.Value.Date != now)
                                {
                                    DatabaseLogger.LogEvent(c.id, "Heartbeat", "Heartbeat OK");
                                    c.LastHeartbeatLog = now;
                                }
                                Logger.LogHeartbeat("DACServer.log", $"[HEARTBEAT] Client {c.id} heartbeat OK");
                            }
                            c.current_heartbeat_count++;
                        }
                        break;

                    case Opcodes.CS.CS_FLAGGED_CHEATER:
                        {
                            c.flagged_cheater = true;
                            DetectionFlags cheat_reason = (DetectionFlags)p.ReadShort();
                            Handlers.HandleClientFlaggedCheater(c, cheat_reason);

                            DatabaseLogger.LogDetection(
                                c.id,
                                cheat_reason.ToString(),
                                "Cheat detected",
                                c.hostname,
                                c.gamecode,
                                c.ip_addr?.ToString(),
                                c.mac_address,
                                c.hardware_id
                            );

                            DetectionFlags[] criticalFlags = new DetectionFlags[] {
                                DetectionFlags.PAGE_PROTECTIONS,
                                DetectionFlags.CODE_INTEGRITY,
                                DetectionFlags.DLL_TAMPERING,
                                DetectionFlags.BAD_IAT,
                                DetectionFlags.OPEN_PROCESS_HANDLES,
                                DetectionFlags.UNSIGNED_DRIVERS,
                                DetectionFlags.INJECTED_ILLEGAL_PROGRAM,
                                DetectionFlags.EXTERNAL_ILLEGAL_PROGRAM,
                                DetectionFlags.MANUAL_MAPPING,
                                DetectionFlags.SUSPENDED_THREAD,
                                DetectionFlags.HYPERVISOR,
                                DetectionFlags.REGISTRY_KEY_MODIFICATIONS,
                                DetectionFlags.DEBUG_WINAPI_DEBUGGER,
                                DetectionFlags.DEBUG_PEB,
                                DetectionFlags.DEBUG_HARDWARE_REGISTERS,
                                DetectionFlags.DEBUG_HEAP_FLAG,
                                DetectionFlags.DEBUG_INT3,
                                DetectionFlags.DEBUG_INT2C,
                                DetectionFlags.DEBUG_CLOSEHANDLE,
                                DetectionFlags.DEBUG_DEBUG_OBJECT,
                                DetectionFlags.DEBUG_VEH_DEBUGGER,
                                DetectionFlags.DEBUG_KERNEL_DEBUGGER,
                                DetectionFlags.DEBUG_TRAP_FLAG,
                                DetectionFlags.DEBUG_DEBUG_PORT,
                                DetectionFlags.DEBUG_PROCESS_DEBUG_FLAGS,
                                DetectionFlags.DEBUG_REMOTE_DEBUGGER,
                                DetectionFlags.DEBUG_DBG_BREAK,
                                DetectionFlags.DEBUG_DBK64_DRIVER
                            };

                            if (criticalFlags.Contains(cheat_reason) && c.ip_addr != null)
                            {
                                string clientIp = c.ip_addr.ToString();
                                string key = clientIp + "_" + cheat_reason.ToString();
                                DateTime now = DateTime.UtcNow;
                                DateTime last;
                                if (TcpProxy.ExternalIllegalTimestamps.TryGetValue(key, out last))
                                {
                                    if ((now - last) > TcpProxy.ExternalIllegalResetInterval)
                                    {
                                        TcpProxy.FailedAttempts[key] = 1;
                                        Logger.LogInfoTag("DACServer.log", $"[PROXY] Reset counter {cheat_reason} for {clientIp} after 12 hours");
                                    }
                                    else
                                    {
                                        TcpProxy.FailedAttempts.AddOrUpdate(key, 1, (k, old) => old + 1);
                                    }
                                }
                                else
                                {
                                    TcpProxy.FailedAttempts[key] = 1;
                                }
                                TcpProxy.ExternalIllegalTimestamps[key] = now;
                                int detectionCount = TcpProxy.FailedAttempts[key];
                                Logger.LogDetection("DACServer.log", $"[PROXY] {cheat_reason} detection for {clientIp}: attempt {detectionCount}/{TcpProxy.MaxFailedAttempts}");
                                RemoveAuthenticatedSession(c);
                                Handlers.RemoveSessionFile(c);
                                try
                                {
                                    if (c.net_client.Client != null && c.net_client.Client.Connected)
                                        c.net_client.Client.Disconnect(false);
                                }
                                catch (ObjectDisposedException) { }
                                c.net_client.Dispose();
                                lock (clientsLock)
                                {
                                    clients.Remove(c);
                                }
                                if (detectionCount >= TcpProxy.MaxFailedAttempts)
                                {
                                    string blockMsg = $"[PROXY][BLOCKED] {cheat_reason} detected for {clientIp} (reached {TcpProxy.MaxFailedAttempts} detection limit, IP banned)";
                                    TcpProxy.BanIpAndUserUid(clientIp, blockMsg);
                                }
                                return SendErrorAndClose(c, "Cheating attempt detected. Connection closed.");
                            }
                        }
                        break;

                    case Opcodes.CS.CS_QUERY_MEMORY:
                        break;
                    case (Opcodes.CS)9999:
                        {
                            string errorMsg = p.ReadString(256);
                            Logger.LogError("DACServer.log", $"[CLIENT ERROR] {errorMsg}");
                            DatabaseLogger.LogDetection(
                                c.id,
                                "ClientError",
                                errorMsg,
                                c.hostname,
                                c.gamecode,
                                c.ip_addr?.ToString(),
                                c.mac_address,
                                c.hardware_id
                            );
                            return false;
                        }
                    case Opcodes.CS.CS_GOODBYE:
                        c.gracefulDisconnect = true;
                        Logger.LogInfoTag("DACServer.log", $"Client {c.id} disconnected gracefully.");
                        DatabaseLogger.LogLogoutEvent(c.id, DateTime.Now);
                        RemoveAuthenticatedSession(c);
                        Handlers.RemoveSessionFile(c);
                        try
                        {
                            if (c?.net_client?.Client != null && c.net_client.Client.Connected)
                                c.net_client.Client.Disconnect(false);
                        }
                        catch (ObjectDisposedException) { }
                        c?.net_client?.Dispose();
                        // Remove client from list immediately to avoid double removal and error log
                        lock (clientsLock)
                        {
                            clients.Remove(c);
                        }
                        return false;

                    case Opcodes.CS.CS_HASH_CHECK:
                        {
                            c.LastHashCheckTime = DateTime.UtcNow;
                            string failReason;
                            bool alreadyLoggedHash;
                            if (!Handlers.HandleClientHashCheck(c, p, out failReason, out alreadyLoggedHash, false))
                            {
                                Logger.LogHashCheck("DACServer.log", $"[HASH_CHECK] Periodic hash check failed: {failReason}");
                                if (!alreadyLoggedHash)
                                {
                                    DatabaseLogger.LogDetection(
                                        c?.id ?? 0,
                                        "InvalidHashCheck",
                                        failReason ?? "Periodic hash check failed for unknown reason",
                                        c?.hostname,
                                        c?.gamecode,
                                        c?.ip_addr?.ToString(),
                                        c?.mac_address,
                                        c?.hardware_id
                                    );
                                }
                                if (c?.ip_addr != null)
                                {
                                    string ip = c.ip_addr.ToString();
                                    DatabaseLogger.BanAccountsByIp(ip, "File integrity check failed. Please reinstall the game.");
                                    int? userUid = DatabaseLogger.GetUserUidByIp(ip);
                                    if (userUid.HasValue)
                                        DatabaseLogger.BanUserUid(userUid.Value, "File integrity check failed. Please reinstall the game.");
                                }
                                SendErrorAndClose(c, "File integrity check failed. Please reinstall the game.");
                                alreadyLogged = true;
                                try
                                {
                                    if (c?.net_client?.Client != null && c.net_client.Client.Connected)
                                        c.net_client.Client.Disconnect(false);
                                    c?.net_client?.Close();
                                }
                                catch (ObjectDisposedException) { }
                                c?.net_client?.Dispose();
                                lock (clientsLock)
                                {
                                    clients.Remove(c);
                                }
                                return false;
                            }
                            else
                            {
                                Logger.LogHashCheck("DACServer.log", $"[HASH_CHECK] Periodic hash check OK for client {c?.id}");
                            }
                        }
                        break;

                    case Opcodes.CS.CS_CLIENTINFO_PERIODIC:
                        {
                            string failReason;
                            bool alreadyLoggedInfo;
                            if (!Handlers.HandleClientInfoPeriodic(c, p, out failReason, out alreadyLoggedInfo))
                            {
                                Logger.LogError("DACServer.log", $"[ERROR][INFO_CHECK] Periodic client info failed: {failReason}");
                                if (!alreadyLoggedInfo)
                                {
                                    DatabaseLogger.LogDetection(
                                        c?.id ?? 0,
                                        "InvalidClientInfoPeriodic",
                                        failReason ?? "Periodic client info failed for unknown reason",
                                        c?.hostname,
                                        c?.gamecode,
                                        c?.ip_addr?.ToString(),
                                        c?.mac_address,
                                        c?.hardware_id
                                    );
                                }
                                if (c?.ip_addr != null)
                                {
                                    string ip = c.ip_addr.ToString();
                                    DatabaseLogger.BanAccountsByIp(ip, "Unauthorized action detected. Session terminated.");
                                    int? userUid = DatabaseLogger.GetUserUidByIp(ip);
                                    if (userUid.HasValue)
                                        DatabaseLogger.BanUserUid(userUid.Value, "Unauthorized action detected. Session terminated.");
                                }
                                SendErrorAndClose(c, "Unauthorized action detected. Session terminated.");
                                alreadyLogged = true;
                                return false;
                            }
                            else
                            {
                                string sessionDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "session");
                                if (!Directory.Exists(sessionDir))
                                    Directory.CreateDirectory(sessionDir);
                                string safeIp = SanitizeFileName(c.ip_addr?.ToString());
                                string safeGameCode = SanitizeFileName(c.gamecode);
                                string sessionFile = Path.Combine(sessionDir, $"{safeIp}_{safeGameCode}.json");
                                if (File.Exists(sessionFile))
                                    File.SetLastWriteTimeUtc(sessionFile, DateTime.UtcNow);
                                Logger.LogInfoTag("DACServer.log", $"[INFO_CHECK] Periodic client info OK for client {c?.id}");
                            }
                        }
                        break;

                    default:
                        Logger.LogError("DACServer.log", "[ERROR] Unknown opcode @ HandlePacket");
                        return SendErrorAndClose(c, "An unexpected error occurred. Please contact support.");
                }
                return true;
            }
            catch (Exception ex)
            {
                Logger.LogError("DACServer.log", "[ERROR] Exception in HandlePacket: " + ex.ToString());
                return false;
            }
        }

        public void Stop()
        {
            isRunning = false;

            // Close all client connections
            foreach (AntiCheatClient client in clients)
            {
                client.net_client.Close();
            }
            clients.Clear();

            // Stop listening for new connections
            listener.Stop();

            Console.WriteLine("Server stopped.");
        }
        private void RemoveAuthenticatedSession(AntiCheatClient c)
        {
            if (c?.ip_addr != null)
            {
                string ip = c.ip_addr.ToString();
                if (AuthenticatedSessions.TryGetValue(ip, out var list))
                {
                    var toRemove = list.FirstOrDefault(s => s.HardwareId == c.hardware_id && s.Mac == c.mac_address && s.GameCode == c.gamecode && s.ClientId == c.id);
                    if (toRemove != null)
                    {
                        list.Remove(toRemove);
                        Logger.LogAuth("DACServer.log", $"[AUTH] Session removed for {ip} (gamecode: {c.gamecode}, hardwareId: {c.hardware_id}, mac: {c.mac_address}, clientId: {c.id})");
                        DatabaseLogger.LogDetection(
                            c.id,
                            "AuthSessionRemoved",
                            $"[AUTH] Session removed for {ip} (gamecode: {c.gamecode}, hardwareId: {c.hardware_id}, mac: {c.mac_address}, clientId: {c.id})",
                            c.hostname,
                            c.gamecode,
                            ip,
                            c.mac_address,
                            c.hardware_id
                        );
                        if (list.Count == 0)
                            AuthenticatedSessions.TryRemove(ip, out _);
                    }
                    else
                    {
                        Logger.LogError("DACServer.log", $"[ERROR][AUTH][INFO] Tried to remove session for {ip}, but none was found.");
                        DatabaseLogger.LogEvent(
                            c.id,
                            "AuthSessionRemoveInfo",
                            $"[ERROR][AUTH][INFO] Tried to remove session for {ip}, but none was found.");
                    }
                }
            }
        }

        private bool HandleClientHashCheck(AntiCheatClient c, PacketReader p, out string failReason, out bool alreadyLogged)
        {
            // Usa la logica statica di Handlers.HandleClientHashCheck per la validazione reale
            return Handlers.HandleClientHashCheck(c, p, out failReason, out alreadyLogged, false);
        }

        private void MonitorPeriodicHashChecks()
        {
            while (isRunning)
            {
                DateTime now = DateTime.UtcNow;
                List<AntiCheatClient> toDisconnect = new List<AntiCheatClient>();
                List<AntiCheatClient> clientsSnapshot;
                lock (clientsLock)
                {
                    clientsSnapshot = clients.ToList();
                }
                foreach (var c in clientsSnapshot)
                {
                    // Se il client non è più connesso, rimuovilo subito
                    if (c.net_client == null || !c.net_client.Connected)
                    {
                        lock (clientsLock)
                        {
                            clients.Remove(c);
                        }
                        continue;
                    }

                    if ((DateTime.UtcNow - c.LastHashCheckTime).TotalMinutes > maxHashCheckDelayMinutes)
                    {
                        // ban e rimozione
                        if (c?.ip_addr != null)
                        {
                            string ip = c.ip_addr.ToString();
                            DatabaseLogger.BanAccountsByIp(ip, "Game file tampering or info mismatch - auto permanent ban");
                            int? userUid = DatabaseLogger.GetUserUidByIp(ip);
                            if (userUid.HasValue)
                                DatabaseLogger.BanUserUid(userUid.Value, "Game file tampering or info mismatch - auto permanent ban");
                        }
                        Logger.LogDetection("DACServer.log", $"[SECURITY] Client {c.id} ({c.ip_addr}) disconnesso per mancato invio info/hash periodico.");
                        DatabaseLogger.LogDetection(
                            c.id,
                            "InfoCheckTimeout",
                            $"Client disconnesso per mancato invio info/hash periodico da oltre {maxInfoCheckDelayMinutes} minuti.",
                            c.hostname,
                            c.gamecode,
                            c.ip_addr?.ToString(),
                            c.mac_address,
                            c.hardware_id
                        );
                        RemoveAuthenticatedSession(c);
                        Handlers.RemoveSessionFile(c);
                        try
                        {
                            if (c?.net_client?.Client != null && c.net_client.Client.Connected)
                                c.net_client.Client.Disconnect(false);
                        }
                        catch (ObjectDisposedException) { }
                        c?.net_client?.Dispose();
                        lock (clientsLock)
                        {
                            clients.Remove(c);
                        }
                    }
                }
                Thread.Sleep(checkIntervalMs);
            }
        }

        // Sanitize file name helper (copied from Handlers)
        private static string SanitizeFileName(string name)
        {
            if (string.IsNullOrEmpty(name)) return "null";
            foreach (char c in Path.GetInvalidFileNameChars())
                name = name.Replace(c, '_');
            return name;
        }

        private bool SendErrorAndClose(AntiCheatClient c, string errorMessage)
        {
            try
            {
                PacketWriter p = new PacketWriter(9999);
                p.WriteString(errorMessage);
                SendBytes(c, p);
                if (c?.net_client?.Client != null && c.net_client.Client.Connected)
                    c.net_client.Client.Disconnect(false);
                c?.net_client?.Dispose();
            }
            catch { }
            return false;
        }
    }
}