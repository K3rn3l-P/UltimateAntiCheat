//UltimateAnticheat Server - By AlSch092 @ Github
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Collections.Concurrent; // Aggiungi questa riga

namespace UACServer.Network
{
    class AnticheatServer
    {
        private const short versionNum = 100;
        private const int heartbeatDelay = 60000; //1 minute between hb's

        private TcpListener listener;
        private List<AntiCheatClient> clients = new List<AntiCheatClient>();
        private bool isRunning = false;
        public static ConcurrentDictionary<string, string> AuthenticatedSessions = new ConcurrentDictionary<string, string>();
        public static Dictionary<DetectionFlags, string> Detections = new Dictionary<DetectionFlags, string>();

        public void Start(string ipAddress, int port)
        {
            listener = new TcpListener(IPAddress.Parse(ipAddress), port);
            listener.Start();
            isRunning = true;

            Logger.Log("DACServer.log", "Server started. Listening for connections...");
            listener.BeginAcceptTcpClient(HandleClientConnected, null); //listen for client connections asynchronously
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

            // Pulizia automatica log vecchi di 7 giorni
            UACServer.Network.DatabaseLogger.CleanupOldLogs();

            TcpClient client = listener.EndAcceptTcpClient(result);

            Logger.Log("DACServer.log", $"Client connected: {((IPEndPoint)client.Client.RemoteEndPoint).Address}");

            AntiCheatClient c = new AntiCheatClient();
            c.id = new Random().Next(0, int.MaxValue); //right now not concerned about duplicate id's, chance is very low to encounter this
            c.net_client = client;
            c.ip_addr = ((IPEndPoint)client.Client.RemoteEndPoint).Address;
            c.connected_at = Environment.TickCount;
            this.clients.Add(c);

            byte[] buffer = new byte[1024];

            // Imposta un timeout per la ricezione del primo pacchetto
            var stream = client.GetStream();
            stream.ReadTimeout = 5000; // 5 secondi

            try
            {
                client.GetStream().BeginRead(buffer, 0, buffer.Length, HandleMessageReceived, new object[] { client, buffer });
            }
            catch (IOException ex)
            {
                Logger.Log("DACServer.log", "Failed to read client data @ HandleClientConnected");
                return;
            }

            listener.BeginAcceptTcpClient(HandleClientConnected, null); //Continue accepting more client connections
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

                int bytesRead = 0;

                try
                {
                    bytesRead = client.GetStream().EndRead(result);
                }
                catch (IOException ex)
                {
                    Logger.Log("DACServer.log", "IOExcpetion @ HandleMessageReceived(): " + ex.Message);
                    Logger.Log("DACServer.log", $"[SECURITY] Connessione chiusa per timeout o errore IO: {ex.Message}");
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
                        RemoveAuthenticatedSession(c); // <-- AGGIUNTO QUI
                    }

                    this.clients.Remove(c);
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
                        Logger.Log("DACServer.log", "Client heartbeat was incorrect, disconnecting client " + c?.hardware_id);
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
                        c?.net_client?.Client?.Disconnect(false);
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
                        Logger.Log("DACServer.log", "Failed to read client data @ HandleMessageReceived");
                        return;
                    }
                }
                else
                {
                    // Nel blocco else (bytesRead <= 0)
                    string ip = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();
                    string removedGamecode;
                    AnticheatServer.AuthenticatedSessions.TryRemove(ip, out removedGamecode);
                    RemoveAuthenticatedSession(c);
                    Logger.Log("DACServer.log", $"Client {((IPEndPoint)client.Client.RemoteEndPoint).Address} disconnected (possibly due to invalid signature or malformed packet).");


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
                            Logger.Log("DACServer.log", $"Client {ip} disconnected gracefully.");
                            DatabaseLogger.LogLogoutEvent(toRemove.id, DateTime.Now);
                        }
                        else
                        {
                            Logger.Log("DACServer.log", $"Client {ip} disconnected (possibly due to invalid signature or malformed packet).");
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
                        clients.Remove(toRemove);
                    }


                    client.Close();
                }

            }
            catch (Exception ex)
            {
                Logger.Log("DACServer.log", "[ERROR] Exception in HandleMessageReceived: " + ex.ToString());
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

                //decrypt buffer
                Cipher(buffer, length);

                PacketReader p = new PacketReader(buffer);
                ushort opcode = p.ReadUShort();

                switch ((Opcodes.CS)opcode)
                {
                    case Opcodes.CS.CS_HELLO: //client hello
                        {
                            string failReason;
                            bool alreadyLoggedHello;
                            if (!Handlers.HandleClientHello(c, p, out failReason, out alreadyLoggedHello))
                            {
                                Logger.Log("DACServer.log", $"Client hello transaction failed: {failReason}");
                                if (!alreadyLoggedHello)
                                {
                                    DatabaseLogger.LogDetection(
                                        c?.id ?? 0,
                                        "InvalidHello",
                                        failReason ?? "Client hello fallito per motivo sconosciuto",
                                        c?.hostname,
                                        c?.gamecode,
                                        c?.ip_addr?.ToString(),
                                        c?.mac_address,
                                        c?.hardware_id
                                    );
                                }
                                alreadyLogged = true;
                                return false;
                            }
                            else
                            {
                                Logger.Log("DACServer.log", "Client info: Hostname=" + c.hostname + ", GameCode=" + c.gamecode + ", ID=" + c.id + ", IP=" + c.ip_addr);
                                AnticheatServer.AuthenticatedSessions.AddOrUpdate(
                                    c.ip_addr.ToString(),
                                    c.gamecode,
                                    (key, oldValue) => c.gamecode
                                );

                                DatabaseLogger.LogClientInfo(
                                    c.hostname,
                                    c.gamecode,
                                    c.id,
                                    c.ip_addr?.ToString(),
                                    c.mac_address,
                                    c.hardware_id,
                                    "Client info"
                                );
                                // AGGIUNGI QUI IL LOG DEL LOGIN
                                DatabaseLogger.LogLoginEvent(
                                    c.id,
                                    c.hostname,
                                    DateTime.Now,
                                    c.ip_addr?.ToString()
                                );
                            }
                            if (!SendClientHello(c))
                            {
                                Logger.Log("DACServer.log", "Client hello transaction failed: failure sending bytes to client");
                                return false;
                            }
                        }
                        break;

                    //heartbeat
                    case Opcodes.CS.CS_HEARTBEAT:
                        {
                            short cookie_len = p.ReadShort();
                            string cookie_str = p.ReadString(128);

                            if (!Handlers.HandleClientHeartbeat(c, cookie_str))
                            {
                                Logger.Log("DACServer.log", "Client heartbeat transaction failed: client heartbeat cookie was incorrect.");
                                DatabaseLogger.LogEvent(c.id, "HeartbeatFailed", "Heartbeat cookie mismatch");
                                return false;
                            }
                            else
                            {
                                Console.WriteLine("Heartbeat from client {0} was successful", c.id);

                                // Logga solo una volta al giorno nel database
                                var now = DateTime.UtcNow.Date;
                                if (c.LastHeartbeatLog == null || c.LastHeartbeatLog.Value.Date != now)
                                {
                                    DatabaseLogger.LogEvent(c.id, "Heartbeat", "Heartbeat OK");
                                    c.LastHeartbeatLog = now;
                                }
                                // Log sempre su file
                                Logger.Log("DACServer.log", $"[HEARTBEAT] Client {c.id} heartbeat OK");
                            }

                            c.current_heartbeat_count++;
                        }
                        break;

                    //flagged as cheater 
                    case Opcodes.CS.CS_FLAGGED_CHEATER:
                        {
                            c.flagged_cheater = true;
                            DetectionFlags cheat_reason = (DetectionFlags)p.ReadShort();
                            Handlers.HandleClientFlaggedCheater(c, cheat_reason);

                            // LOGGA LA DETECTION
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

                            // --- AGGIUNGI QUESTO BLOCCO ---
                            if (cheat_reason == DetectionFlags.EXTERNAL_ILLEGAL_PROGRAM && c.ip_addr != null)
                            {
                                string clientIp = c.ip_addr.ToString();
                                int externalIllegalCount = TcpProxy.FailedAttempts.AddOrUpdate(clientIp + "_external", 1, (key, old) => old + 1);
                                if (externalIllegalCount >= TcpProxy.MaxFailedAttempts)
                                {
                                    string blockMsg = $"[PROXY][BLOCKED] EXTERNAL_ILLEGAL_PROGRAM Unauthenticated client {clientIp} ({TcpProxy.MaxFailedAttempts} attempt limit reached, IP banned)";
                                    TcpProxy.BanIpAndUserUid(clientIp, blockMsg);
                                }
                            }
                            // --- FINE BLOCCO ---
                        }
                        break;

                    case Opcodes.CS.CS_QUERY_MEMORY: //todo: finish this
                        {

                        }
                        break;
                    case (Opcodes.CS)9999:
                        {
                            string errorMsg = p.ReadString(256); // o la lunghezza che preferisci
                            Logger.Log("DACServer.log", $"[CLIENT ERROR] {errorMsg}");
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
                            return false; // disconnessione
                        }
                    case Opcodes.CS.CS_GOODBYE:
                        c.gracefulDisconnect = true;
                        Logger.Log("DACServer.log", $"Client {c.id} disconnected gracefully.");
                        DatabaseLogger.LogLogoutEvent(c.id, DateTime.Now);
                        RemoveAuthenticatedSession(c); // <-- AGGIUNTO QUI

                        return false; // chiudi la connessione dopo il goodbye

                    default:
                        Logger.Log("DACServer.log", "Unknown opcode @ HandlePacket");
                        return false;
                }
                ;

                return true;
            }
            catch (Exception ex)
            {
                Logger.Log("DACServer.log", "[ERROR] Exception in HandlePacket: " + ex.ToString());
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
                string removedGamecode;
                if (AuthenticatedSessions.TryRemove(ip, out removedGamecode))
                {
                    Logger.Log("DACServer.log", $"[AUTH] Session removed for {ip} (gamecode: {removedGamecode})");
                    DatabaseLogger.LogDetection(
                        c.id,
                        "AuthSessionRemoved",
                        $"[AUTH] Session removed for {ip} (gamecode: {removedGamecode})",
                        c.hostname,
                        removedGamecode,
                        ip,
                        c.mac_address,
                        c.hardware_id
                    );
                }
                else
                {
                    Logger.Log("DACServer.log", $"[AUTH][WARN] Tried to remove session for {ip}, but none was found.");
                    DatabaseLogger.LogDetection(
                        c.id,
                        "AuthSessionRemoveWarn",
                        $"[AUTH][WARN] Tried to remove session for {ip}, but none was found.",
                        c.hostname,
                        c.gamecode,
                        ip,
                        c.mac_address,
                        c.hardware_id
                    );
                }
            }
        }

    }

}