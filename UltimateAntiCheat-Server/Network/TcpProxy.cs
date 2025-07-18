using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using UACServer;
using UACServer.Network;

public class TcpProxy
{
    // Campo statico per tracciare le connessioni attive per IP
    private static readonly ConcurrentDictionary<string, object> ActiveConnections = new ConcurrentDictionary<string, object>();
    public static readonly ConcurrentDictionary<string, int> FailedAttempts = new ConcurrentDictionary<string, int>();
    public const int MaxFailedAttempts = 3;

    // Per il reset temporale dei tentativi EXTERNAL_ILLEGAL_PROGRAM
    public static readonly ConcurrentDictionary<string, DateTime> ExternalIllegalTimestamps = new ConcurrentDictionary<string, DateTime>();
    public static readonly TimeSpan ExternalIllegalResetInterval = TimeSpan.FromHours(12);

    public static void BanIpAndUserUid(string clientIp, string reason)
    {
        DatabaseLogger.BanAccountsByIp(clientIp, reason);
        DatabaseLogger.LogIpBlocked(clientIp, reason);
        Logger.Log("DACServer.log", reason);

        int? uid = DatabaseLogger.GetUserUidByIp(clientIp);
        if (uid.HasValue)
            DatabaseLogger.BanUserUid(uid.Value, reason);
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
        Logger.Log("DACServer.log", $"[PROXY] Listening on {listenIp}:{listenPort}, forwarding to {targetHost}:{targetPort}");

        while (true)
        {
            var client = listener.AcceptTcpClient();
            Logger.Log("DACServer.log", $"[PROXY] Accepted connection from {client.Client.RemoteEndPoint}");
            ThreadPool.QueueUserWorkItem(_ => HandleClient(client));
        }
    }

    private void HandleClient(TcpClient client)
    {
        string clientIp = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();

        int? userUid = DatabaseLogger.GetUserUidByIp(clientIp);

        // Prima del controllo ban
        bool wasBanned = false;
        if (FailedAttempts.TryGetValue(clientIp, out int failedCount) && failedCount >= MaxFailedAttempts)
        {
            // Se il database ora NON lo considera più bannato, resetta
            if (!DatabaseLogger.IsIpBanned(clientIp))
            {
                FailedAttempts.TryRemove(clientIp, out _);
                Logger.Log("DACServer.log", $"[PROXY] Reset dei tentativi falliti per {clientIp} (IP sbloccato nel database)");
            }
            wasBanned = true;
        }

        if (DatabaseLogger.IsIpBanned(clientIp) || (userUid.HasValue && DatabaseLogger.IsUserUidBanned(userUid.Value)))
        {
            string reason = userUid.HasValue
                ? $"[PROXY][BLOCKED] Connessione rifiutata: UserUID {userUid.Value} bannato (Users_Bann o Status = -5)"
                : $"[PROXY][BLOCKED] Connessione rifiutata: IP {clientIp} bannato (Status = -5)";
            Logger.Log("DACServer.log", reason);
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
            return;
        }

        Logger.Log("DACServer.log", $"[PROXY] Verifying client {clientIp}");

        int maxAttempts = 3; // DICHIARA QUI maxAttempts

        string expectedGamecode = null;
        bool isAuthenticated = false;
        for (int i = 0; i < maxAttempts; i++)
        {
            if (AnticheatServer.AuthenticatedSessions.TryGetValue(clientIp, out expectedGamecode))
            {
                isAuthenticated = true;
                break;
            }
            Thread.Sleep(500);
        }

        string connectionKey = $"{listenPort}:{clientIp}:{expectedGamecode}";

        bool added = ActiveConnections.TryAdd(connectionKey, null);
        if (!added)
        {
            Logger.Log("DACServer.log", $"[PROXY][BLOCKED] Connessione parallela già attiva per {connectionKey}");
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
            return;
        }

        if (!isAuthenticated)
        {
            Logger.Log("DACServer.log", $"[PROXY][BLOCKED] Client non autenticato: {clientIp}");
            DatabaseLogger.LogDetection(
                0,
                "ProxyBlockedUnauth",
                $"[PROXY][BLOCKED] Client non autenticato: {clientIp}",
                null,
                null,
                clientIp,
                null,
                null
            );
            client.Close();
            ActiveConnections.TryRemove(connectionKey, out _);

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

        Logger.Log("DACServer.log", $"[PROXY] Client {clientIp} authenticated successfully.");

        using (client)
        using (var server = new TcpClient())
        {
            try
            {
                server.Connect(targetHost, targetPort);
                Logger.Log("DACServer.log", $"[PROXY] Connected to target {targetHost}:{targetPort}");

                var clientToServer = new Thread(() => Forward(client.GetStream(), server.GetStream()));
                var serverToClient = new Thread(() => Forward(server.GetStream(), client.GetStream()));
                clientToServer.Start();
                serverToClient.Start();

                clientToServer.Join();
                serverToClient.Join();
            }
            catch (Exception ex)
            {
                Logger.Log("DACServer.log", $"[PROXY][ERROR] {ex}");
            }
            finally
            {
                ActiveConnections.TryRemove(connectionKey, out _);
            }
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
