using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using UACServer;
using UACServer.Network;
using System.Collections.Generic;

public class TcpProxy
{
    // Campo statico per tracciare le connessioni attive per IP
    private static readonly ConcurrentDictionary<string, object> ActiveConnections = new ConcurrentDictionary<string, object>();
    public static readonly ConcurrentDictionary<string, int> FailedAttempts = new ConcurrentDictionary<string, int>();
    public const int MaxFailedAttempts = 3;

    // Nuovo: traccia tutte le connessioni attive per IP
    private static readonly ConcurrentDictionary<string, ConcurrentBag<TcpClient>> ActiveTcpClients = new ConcurrentDictionary<string, ConcurrentBag<TcpClient>>();

    // Per il reset temporale dei tentativi EXTERNAL_ILLEGAL_PROGRAM
    public static readonly ConcurrentDictionary<string, DateTime> ExternalIllegalTimestamps = new ConcurrentDictionary<string, DateTime>();
    public static readonly TimeSpan ExternalIllegalResetInterval = TimeSpan.FromHours(12);

    private const int GracePeriodMs = 7000; // 7 secondi di tolleranza per disconnessioni temporanee

    public static void BanIpAndUserUid(string clientIp, string reason)
    {
        DatabaseLogger.BanAccountsByIp(clientIp, reason);
        DatabaseLogger.LogIpBlocked(clientIp, reason);
        Logger.Log("DACServer.log", reason);

        int? uid = DatabaseLogger.GetUserUidByIp(clientIp);
        if (uid.HasValue)
            DatabaseLogger.BanUserUid(uid.Value, reason);
        // Chiudi tutte le connessioni attive per quell'IP
        CloseConnectionsForIp(clientIp);
    }

    // Chiude tutte le connessioni attive per un IP
    public static void CloseConnectionsForIp(string ip)
    {
        if (ActiveTcpClients.TryRemove(ip, out var bag))
        {
            foreach (var client in bag)
            {
                try { client.Close(); } catch { }
                Logger.LogDetection("DACServer.log", $"[SECURITY][PROXY] Connessione chiusa per IP bannato: {ip}");
            }
        }
    }

    // Rimuove un TcpClient dal bag associato all'IP
    private static void RemoveClientFromBag(string ip, TcpClient client)
    {
        if (ActiveTcpClients.TryGetValue(ip, out var bag))
        {
            // ConcurrentBag non supporta Remove, quindi ricrea il bag senza il client chiuso
            var newBag = new ConcurrentBag<TcpClient>();
            foreach (var c in bag)
            {
                if (!object.ReferenceEquals(c, client))
                    newBag.Add(c);
            }
            ActiveTcpClients[ip] = newBag;
        }
    }

    private readonly string listenIp;
    private readonly int listenPort;
    private readonly string targetHost;
    private readonly int targetPort;

    public TcpProxy(string listenIp, int listenPort, string targetHost, int targetPort)
    {
        this.listenIp = listenIp;
        this.listenPort = listenPort;
        this.targetHost = targetHost;
        this.targetPort = targetPort;
    }

    public void Start()
    {
        var listener = new TcpListener(IPAddress.Parse(listenIp), listenPort);
        listener.Start();
        Logger.LogProxy("DACServer.log", $"[PROXY] Listening on {listenIp}:{listenPort}, forwarding to {targetHost}:{targetPort}");

        while (true)
        {
            var client = listener.AcceptTcpClient();
            string clientIp = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();
            // BLOCCO IMMEDIATO: se l'IP è bannato, chiudi subito la connessione senza nemmeno avviare HandleClient
            if (DatabaseLogger.IsIpBanned(clientIp))
            {
                Logger.LogDetection("DACServer.log", $"[SECURITY][PROXY][BLOCKED] Connessione rifiutata subito: IP {clientIp} bannato (Status = -5)");
                DatabaseLogger.LogDetection(
                    0,
                    "ProxyBlockedBanned",
                    $"[PROXY][BLOCKED] Connessione rifiutata subito: IP {clientIp} bannato (Status = -5)",
                    null,
                    null,
                    clientIp,
                    null,
                    null
                );
                client.Close();
                client.Dispose();
                continue;
            }
            Logger.LogProxy("DACServer.log", $"[PROXY] Accepted connection from {client.Client.RemoteEndPoint}");
            ThreadPool.QueueUserWorkItem(_ => HandleClient(client));
        }
    }

    private void HandleClient(TcpClient client)
    {
        string clientIp = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();

        // BLOCCO IMMEDIATO: se l'IP è bannato, chiudi subito la connessione
        if (DatabaseLogger.IsIpBanned(clientIp))
        {
            Logger.LogDetection("DACServer.log", $"[SECURITY][PROXY][BLOCKED] Connessione rifiutata: IP {clientIp} bannato (Status = -5)");
            DatabaseLogger.LogDetection(
                0,
                "ProxyBlockedBanned",
                $"[PROXY][BLOCKED] Connessione rifiutata: IP {clientIp} bannato (Status = -5)",
                null,
                null,
                clientIp,
                null,
                null
            );
            client.Close();
            client.Dispose(); // chiusura definitiva
            RemoveClientFromBag(clientIp, client);
            return;
        }

        // Registra la connessione attiva per l'IP
        var bag = ActiveTcpClients.GetOrAdd(clientIp, _ => new ConcurrentBag<TcpClient>());
        bag.Add(client);

        int? userUid = DatabaseLogger.GetUserUidByIp(clientIp);

        // Prima del controllo ban
        bool wasBanned = false;
        if (FailedAttempts.TryGetValue(clientIp, out int failedCount) && failedCount >= MaxFailedAttempts)
        {
            // Se il database ora NON lo considera più bannato, resetta
            if (!DatabaseLogger.IsIpBanned(clientIp))
            {
                FailedAttempts.TryRemove(clientIp, out _);
                Logger.LogProxy("DACServer.log", $"[PROXY] Reset dei tentativi falliti per {clientIp} (IP sbloccato nel database)");
            }
            wasBanned = true;
        }

        if (DatabaseLogger.IsIpBanned(clientIp) || (userUid.HasValue && DatabaseLogger.IsUserUidBanned(userUid.Value)))
        {
            string reason = userUid.HasValue
                ? $"[SECURITY][PROXY][BLOCKED] Connessione rifiutata: UserUID {userUid.Value} bannato (Users_Bann o Status = -5)"
                : $"[SECURITY][PROXY][BLOCKED] Connessione rifiutata: IP {clientIp} bannato (Status = -5)";
            Logger.LogDetection("DACServer.log", reason);
            DatabaseLogger.LogDetection(
                userUid ?? 0,
                "ProxyBlockedBanned",
                reason,
                null,
                null,
                clientIp,
                null,
                null
            );
            client.Close();
            RemoveClientFromBag(clientIp, client);
            return;
        }

        Logger.LogProxy("DACServer.log", $"[PROXY] Verifying client {clientIp}");

        int maxAttempts = 3;
        List<UACServer.Network.SessionInfo> sessionList = null;
        bool isAuthenticated = false;
        for (int i = 0; i < maxAttempts; i++)
        {
            if (UACServer.Network.AnticheatServer.AuthenticatedSessions.TryGetValue(clientIp, out sessionList))
            {
                // Cerca una sessione che abbia hardwareId/mac/gameCode/clientId diversi (max 2)
                if (sessionList != null && sessionList.Count <= 2)
                {
                    isAuthenticated = true;
                    break;
                }
            }
            Thread.Sleep(500);
        }
        // Usa la prima sessione per la chiave di connessione (se esiste)
        string expectedGamecode = sessionList != null && sessionList.Count > 0 ? sessionList[0].GameCode : null;
        string connectionKey = $"{listenPort}:{clientIp}:{expectedGamecode}";

        bool added = ActiveConnections.TryAdd(connectionKey, null);
        if (!added)
        {
            Logger.LogDetection("DACServer.log", $"[SECURITY][PROXY][BLOCKED] Connessione parallela già attiva per {connectionKey}");
            DatabaseLogger.LogDetection(
                0,
                "ProxyBlockedParallel",
                $"[PROXY][BLOCKED] Connessione parallela già attiva per {connectionKey}",
                null,
                null,
                clientIp,
                null,
                null
            );
            client.Close();
            ActiveConnections.TryRemove(connectionKey, out _);
            RemoveClientFromBag(clientIp, client);
            return;
        }

        if (!isAuthenticated)
        {
            Logger.LogDetection("DACServer.log", $"[SECURITY][PROXY][BLOCKED] Client non autenticato o limite sessioni raggiunto: {clientIp}");
            DatabaseLogger.LogDetection(
                0,
                "ProxyBlockedUnauth",
                $"[PROXY][BLOCKED] Client non autenticato o limite sessioni raggiunto: {clientIp}",
                null,
                null,
                clientIp,
                null,
                null
            );
            client.Close();
            ActiveConnections.TryRemove(connectionKey, out _);
            RemoveClientFromBag(clientIp, client);

            // Incrementa i tentativi falliti
            int failed = FailedAttempts.AddOrUpdate(clientIp, 1, (key, old) => old + 1);
            if (failed == MaxFailedAttempts)
            {
                string blockMsg = $"[BLOCKED] Unauthenticated client: {clientIp} ({MaxFailedAttempts} attempt limit reached, IP banned)";
                BanIpAndUserUid(clientIp, blockMsg);
            }

            return;
        }

        // Solo per il proxy di gioco (porta 30810)
        if (listenPort == 30810)
        {
            UACServer.Network.DatabaseLogger.UpdateLoginAttemptIpByRealIp(clientIp);
        }

        Logger.LogProxy("DACServer.log", $"[PROXY] Client {clientIp} authenticated successfully.");

        // --- AVVIA IL THREAD DI CONTROLLO PERIODICO BAN IP ---
        Thread banCheckThread = new Thread(() =>
        {
            try
            {
                while (true)
                {
                    Thread.Sleep(TimeSpan.FromMinutes(20));
                    if (DatabaseLogger.IsIpBanned(clientIp))
                    {
                        Logger.LogDetection("DACServer.log", $"[SECURITY][PROXY][PERIODIC BLOCK] IP {clientIp} bannato durante la sessione. Chiudo la connessione.");
                        DatabaseLogger.LogDetection(
                            0,
                            "ProxyPeriodicBlockedBanned",
                            $"[PROXY][PERIODIC BLOCK] IP {clientIp} bannato durante la sessione. Connessione chiusa.",
                            null,
                            null,
                            clientIp,
                            null,
                            null
                        );
                        try { client.Close(); } catch { }
                        return;
                    }
                }
            }
            catch (ThreadAbortException) { }
        });
        banCheckThread.IsBackground = true;
        banCheckThread.Start();

        using (client)
        using (var server = new TcpClient())
        {
            try
            {
                server.Connect(targetHost, targetPort);
                Logger.LogProxy("DACServer.log", $"[PROXY] Connected to target {targetHost}:{targetPort}");

                // Forwarding con monitoraggio e grace period
                var cts = new CancellationTokenSource();
                Exception forwardException = null;

                Thread clientToServer = new Thread(() =>
                {
                    try { ForwardWithGrace(client.GetStream(), server.GetStream(), cts.Token); }
                    catch (Exception ex) { forwardException = ex; }
                    finally { cts.Cancel(); }
                });
                Thread serverToClient = new Thread(() =>
                {
                    try { ForwardWithGrace(server.GetStream(), client.GetStream(), cts.Token); }
                    catch (Exception ex) { forwardException = ex; }
                    finally { cts.Cancel(); }
                });
                clientToServer.Start();
                serverToClient.Start();

                // Attendi che uno dei due thread termini
                while (clientToServer.IsAlive || serverToClient.IsAlive)
                {
                    if (cts.IsCancellationRequested)
                        break;
                    Thread.Sleep(100);
                }

                // Grace period: attendi qualche secondo prima di chiudere tutto
                Logger.LogProxy("DACServer.log", $"[PROXY] Grace period di {GracePeriodMs / 1000} secondi prima di chiudere le connessioni per {clientIp}");
                Thread.Sleep(GracePeriodMs);

                try { client.Close(); } catch { }
                try { server.Close(); } catch { }
            }
            catch (Exception ex)
            {
                Logger.Log("DACServer.log", $"[PROXY][ERROR] {ex}");
            }
            finally
            {
                ActiveConnections.TryRemove(connectionKey, out _);
                RemoveClientFromBag(clientIp, client);
            }
        }
    }

    // Nuova funzione di forwarding con monitoraggio
    private void ForwardWithGrace(NetworkStream from, NetworkStream to, CancellationToken token)
    {
        try
        {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while (!token.IsCancellationRequested && (bytesRead = from.Read(buffer, 0, buffer.Length)) > 0)
            {
                to.Write(buffer, 0, bytesRead);
                to.Flush();
            }
        }
        catch (Exception ex)
        {
            if (ex.Message.Contains("WSACancelBlockingCall"))
                Logger.LogForward("DACServer.log", "[PROXY][FORWARD][INFO] Stream TCP chiuso per cambio porta login/Game (WSACancelBlockingCall): la sessione applicativa potrebbe essere ancora attiva.");
            else if (ex.Message.Contains("forcibly closed by the remote host"))
                Logger.LogForward("DACServer.log", "[PROXY][FORWARD][INFO] Connessione chiusa dal client.");
            else
                Logger.LogForward("DACServer.log", $"[PROXY][FORWARD][ERROR] Connessione chiusa o errore: {ex.Message}");
        }
    }

    private void Forward(NetworkStream from, NetworkStream to)
    {
        try
        {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = from.Read(buffer, 0, buffer.Length)) > 0)
            {
                to.Write(buffer, 0, bytesRead);
                to.Flush();
            }
        }
        catch { /* Connessione chiusa, ignora */ }
    }
}
