using System;
using System.Data.SqlClient;
using System.Configuration;

namespace UACServer.Network
{
    public static class DatabaseLogger
    {
        private static readonly string connectionString =
            ConfigurationManager.ConnectionStrings["GameLogDb"].ConnectionString;

        public static bool IsIpBanned(string ip)
        {
            try
            {
                using (var conn = new SqlConnection(connectionString))
                {
                    conn.Open();
                    var cmd = new SqlCommand(
                        "SELECT COUNT(*) FROM [PS_UserData].[dbo].[Users_Master] WHERE [UserIp] = @IP AND [Status] = -5", conn);
                    cmd.Parameters.AddWithValue("@IP", ip);
                    int count = (int)cmd.ExecuteScalar();
                    return count > 0;
                }
            }
            catch (Exception ex)
            {
                Logger.Log("DACServer.log", "[DB][ERROR] IsIpBanned exception: " + ex.ToString());
                // In caso di errore, meglio non bloccare per evitare falsi positivi
                return false;
            }
        }

        public static void LogClientInfo(string hostname, string gameCode, int clientId, string ip, string mac, string hardwareId, string message)
        {
            Logger.Log("DACServer.log", $"[DB] LogClientInfo START: clientId={clientId}, hostname={hostname}, gameCode={gameCode}, ip={ip}, mac={mac}, hardwareId={hardwareId}, message={message}");
            try
            {
                using (var conn = new SqlConnection(connectionString))
                {
                    conn.Open();
                    var cmd = new SqlCommand(
                        "INSERT INTO gameLog (LogTime, Hostname, GameCode, ClientId, IP, MAC, HardwareId, Message) VALUES (GETDATE(), @Hostname, @GameCode, @ClientId, @IP, @MAC, @HardwareId, @Message)", conn);
                    cmd.Parameters.AddWithValue("@Hostname", (object)hostname ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@GameCode", (object)gameCode ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@ClientId", clientId);
                    cmd.Parameters.AddWithValue("@IP", (object)ip ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@MAC", (object)mac ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@HardwareId", (object)hardwareId ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@Message", (object)message ?? DBNull.Value);
                    cmd.ExecuteNonQuery();
                }
                Logger.Log("DACServer.log", "[DB] LogClientInfo SUCCESS");
            }
            catch (Exception ex)
            {
                Logger.Log("DACServer.log", "[DB][ERROR] LogClientInfo exception: " + ex.ToString());
            }
        }

        public static void LogDetection(
    int clientId,
    string detectionType,
    string details,
    string hostname = null,
    string gameCode = null,
    string ip = null,
    string mac = null,
    string hardwareId = null)
        {
            Logger.Log("DACServer.log", $"[DB] LogDetection START: clientId={clientId}, detectionType={detectionType}, details={details}, hostname={hostname}, gameCode={gameCode}, ip={ip}, mac={mac}, hardwareId={hardwareId}");
            try
            {
                using (var conn = new SqlConnection(connectionString))
                {
                    conn.Open();
                    var cmd = new SqlCommand(
                        "INSERT INTO gameLog (LogTime, Hostname, GameCode, ClientId, IP, MAC, HardwareId, Message) " +
                        "VALUES (GETDATE(), @Hostname, @GameCode, @ClientId, @IP, @MAC, @HardwareId, @Message)", conn);
                    cmd.Parameters.AddWithValue("@Hostname", (object)hostname ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@GameCode", (object)gameCode ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@ClientId", clientId);
                    cmd.Parameters.AddWithValue("@IP", (object)ip ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@MAC", (object)mac ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@HardwareId", (object)hardwareId ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@Message", $"[DETECTION] {detectionType}: {details}");
                    cmd.ExecuteNonQuery();
                }
                Logger.Log("DACServer.log", "[DB] LogDetection SUCCESS");
            }
            catch (Exception ex)
            {
                Logger.Log("DACServer.log", "[DB][ERROR] LogDetection exception: " + ex.ToString());
            }
        }


        public static void LogLoginEvent(int clientId, string username, DateTime loginTime, string ip)
        {
            Logger.Log("DACServer.log", $"[DB] LogLoginEvent START: clientId={clientId}, username={username}, loginTime={loginTime}, ip={ip}");
            try
            {
                using (var conn = new SqlConnection(connectionString))
                {
                    conn.Open();
                    var cmd = new SqlCommand(
                        "INSERT INTO LoginEvents (ClientId, Username, LoginTime, IP) VALUES (@ClientId, @Username, @LoginTime, @IP)", conn);
                    cmd.Parameters.AddWithValue("@ClientId", clientId);
                    cmd.Parameters.AddWithValue("@Username", (object)username ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@LoginTime", loginTime);
                    cmd.Parameters.AddWithValue("@IP", (object)ip ?? DBNull.Value);
                    cmd.ExecuteNonQuery();
                }
                Logger.Log("DACServer.log", "[DB] LogLoginEvent SUCCESS");
            }
            catch (Exception ex)
            {
                Logger.Log("DACServer.log", "[DB][ERROR] LogLoginEvent exception: " + ex.ToString());
            }
        }

        public static void LogLogoutEvent(int clientId, DateTime logoutTime)
        {
            Logger.Log("DACServer.log", $"[DB] LogLogoutEvent START: clientId={clientId}, logoutTime={logoutTime}");
            try
            {
                using (var conn = new SqlConnection(connectionString))
                {
                    conn.Open();
                    var cmd = new SqlCommand(
                        "INSERT INTO LogoutEvents (ClientId, LogoutTime) VALUES (@ClientId, @LogoutTime)", conn);
                    cmd.Parameters.AddWithValue("@ClientId", clientId);
                    cmd.Parameters.AddWithValue("@LogoutTime", logoutTime);
                    cmd.ExecuteNonQuery();
                }
                Logger.Log("DACServer.log", "[DB] LogLogoutEvent SUCCESS");
            }
            catch (Exception ex)
            {
                Logger.Log("DACServer.log", "[DB][ERROR] LogLogoutEvent exception: " + ex.ToString());
            }
        }

        public static void LogEvent(int clientId, string eventType, string eventData)
        {
            Logger.Log("DACServer.log", $"[DB] LogEvent START: clientId={clientId}, eventType={eventType}, eventData={eventData}");
            try
            {
                using (var conn = new SqlConnection(connectionString))
                {
                    conn.Open();
                    var cmd = new SqlCommand(
                        "INSERT INTO EventLog (EventTime, ClientId, EventType, EventData) VALUES (GETDATE(), @ClientId, @EventType, @EventData)", conn);
                    cmd.Parameters.AddWithValue("@ClientId", clientId);
                    cmd.Parameters.AddWithValue("@EventType", (object)eventType ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@EventData", (object)eventData ?? DBNull.Value);
                    cmd.ExecuteNonQuery();
                }
                Logger.Log("DACServer.log", "[DB] LogEvent SUCCESS");
            }
            catch (Exception ex)
            {
                Logger.Log("DACServer.log", "[DB][ERROR] LogEvent exception: " + ex.ToString());
            }
        }
        public static void BanAccountsByIp(string ip, string reason = "[PROXY][BLOCKED]")
        {
            try
            {
                using (var conn = new SqlConnection(connectionString))
                {
                    conn.Open();
                    var cmd = new SqlCommand(
                        "UPDATE [PS_UserData].[dbo].[Users_Master] SET [Status] = -5 WHERE [UserIp] = @IP", conn);
                    cmd.Parameters.AddWithValue("@IP", ip);
                    cmd.ExecuteNonQuery();
                }
                Logger.Log("DACServer.log", $"[DB] BanAccountsByIp: Banned all accounts with IP {ip}");
            }
            catch (Exception ex)
            {
                Logger.Log("DACServer.log", "[DB][ERROR] BanAccountsByIp exception: " + ex.ToString());
            }
        }
        public static int? GetUserUidByIp(string ip)
        {
            try
            {
                using (var conn = new SqlConnection(connectionString))
                {
                    conn.Open();
                    var cmd = new SqlCommand(
                        "SELECT TOP 1 [UserUID] FROM [PS_UserData].[dbo].[Users_Master] WHERE [UserIp] = @IP", conn);
                    cmd.Parameters.AddWithValue("@IP", ip);
                    var result = cmd.ExecuteScalar();
                    if (result != null && result != DBNull.Value)
                        return Convert.ToInt32(result);
                    return null;
                }
            }
            catch (Exception ex)
            {
                Logger.Log("DACServer.log", "[DB][ERROR] GetUserUidByIp exception: " + ex.ToString());
                return null;
            }
        }
        public static bool IsUserUidBanned(int userUid)
        {
            try
            {
                using (var conn = new SqlConnection(connectionString))
                {
                    conn.Open();
                    var cmd = new SqlCommand(
                        "SELECT COUNT(*) FROM [PS_UserData].[dbo].[Users_Bann] WHERE [UserUID] = @UserUID AND [Sbandate] > GETDATE()", conn);
                    cmd.Parameters.AddWithValue("@UserUID", userUid);
                    int count = (int)cmd.ExecuteScalar();
                    return count > 0;
                }
            }
            catch (Exception ex)
            {
                Logger.Log("DACServer.log", "[DB][ERROR] IsUserUidBanned exception: " + ex.ToString());
                return false;
            }
        }
        public static void BanUserUid(int userUid, string reason, string gmId = "DAC Server")
        {
            try
            {
                using (var conn = new SqlConnection(connectionString))
                {
                    conn.Open();
                    var cmd = new SqlCommand(
                        "INSERT INTO [PS_UserData].[dbo].[Users_Bann] ([UserUID], [DaysBann], [BanDate], [Sbandate], [Reason], [GM_ID]) " +
                        "VALUES (@UserUID, 0, @BanDate, @Sbandate, @Reason, @GM_ID)", conn);
                    cmd.Parameters.AddWithValue("@UserUID", userUid);
                    cmd.Parameters.AddWithValue("@BanDate", DateTime.Now);
                    cmd.Parameters.AddWithValue("@Sbandate", new DateTime(2099, 1, 1)); // ban indefinito
                    cmd.Parameters.AddWithValue("@Reason", reason);
                    cmd.Parameters.AddWithValue("@GM_ID", gmId);
                    cmd.ExecuteNonQuery();
                }
                Logger.Log("DACServer.log", $"[DB] BanUserUid: UserUID {userUid} banned in Users_Bann.");
            }
            catch (Exception ex)
            {
                Logger.Log("DACServer.log", "[DB][ERROR] BanUserUid exception: " + ex.ToString());
            }
        }

        public static void LogIpBlocked(string ip, string message, string hostname = null, string gameCode = null, int? clientId = null, string mac = null, string hardwareId = null)
        {
            try
            {
                using (var conn = new SqlConnection(connectionString))
                {
                    conn.Open();
                    var cmd = new SqlCommand(
                        "INSERT INTO [PS_GameLog].[dbo].[IPBlocked] (LogTime, Hostname, GameCode, ClientId, IP, MAC, HardwareId, Message) " +
                        "VALUES (GETDATE(), @Hostname, @GameCode, @ClientId, @IP, @MAC, @HardwareId, @Message)", conn);
                    cmd.Parameters.AddWithValue("@Hostname", (object)hostname ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@GameCode", (object)gameCode ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@ClientId", (object)clientId ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@IP", (object)ip ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@MAC", (object)mac ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@HardwareId", (object)hardwareId ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@Message", (object)message ?? DBNull.Value);
                    cmd.ExecuteNonQuery();
                }
                Logger.Log("DACServer.log", $"[DB] LogIpBlocked: IP {ip} blocked and logged.");
            }
            catch (Exception ex)
            {
                Logger.Log("DACServer.log", "[DB][ERROR] LogIpBlocked exception: " + ex.ToString());
            }
        }
        public static void CleanupOldLogs(int days = 1)
        {
            try
            {
                using (var conn = new SqlConnection(connectionString))
                {
                    conn.Open();

                    // gameLog
                    var cmd1 = new SqlCommand(
                        "DELETE FROM [PS_GameLog].[dbo].[gameLog] WHERE LogTime < DATEADD(day, -@Days, GETDATE())", conn);
                    cmd1.Parameters.AddWithValue("@Days", days);
                    int rows1 = cmd1.ExecuteNonQuery();

                    // LogoutEvents
                    var cmd2 = new SqlCommand(
                        "DELETE FROM [PS_GameLog].[dbo].[LogoutEvents] WHERE LogoutTime < DATEADD(day, -@Days, GETDATE())", conn);
                    cmd2.Parameters.AddWithValue("@Days", days);
                    int rows2 = cmd2.ExecuteNonQuery();

                    // LoginEvents
                    var cmd3 = new SqlCommand(
                        "DELETE FROM [PS_GameLog].[dbo].[LoginEvents] WHERE LoginTime < DATEADD(day, -@Days, GETDATE())", conn);
                    cmd3.Parameters.AddWithValue("@Days", days);
                    int rows3 = cmd3.ExecuteNonQuery();

                    // EventLog
                    var cmd4 = new SqlCommand(
                        "DELETE FROM [PS_GameLog].[dbo].[EventLog] WHERE EventTime < DATEADD(day, -@Days, GETDATE())", conn);
                    cmd4.Parameters.AddWithValue("@Days", days);
                    int rows4 = cmd4.ExecuteNonQuery();

                    // IPBlocked
                    var cmd5 = new SqlCommand(
                        "DELETE FROM [PS_GameLog].[dbo].[IPBlocked] WHERE LogTime < DATEADD(day, -@Days, GETDATE())", conn);
                    cmd5.Parameters.AddWithValue("@Days", days);
                    int rows5 = cmd5.ExecuteNonQuery();

                    string logMsg = $"[DB] CleanupOldLogs: Deleted {rows1} from gameLog, {rows2} from LogoutEvents, {rows3} from LoginEvents, {rows4} from EventLog, {rows5} from IPBlocked.";
                    Logger.Log("DACServer.log", logMsg);
                    Console.WriteLine(logMsg);
                }
            }
            catch (Exception ex)
            {
                Logger.Log("DACServer.log", "[DB][ERROR] CleanupOldLogs exception: " + ex.ToString());
                Console.WriteLine("[DB][ERROR] CleanupOldLogs exception: " + ex.ToString());
            }
        }


    }
}
