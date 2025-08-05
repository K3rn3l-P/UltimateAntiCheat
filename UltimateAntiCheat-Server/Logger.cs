//UltimateAnticheat Server - By AlSch092 @ Github
using System;
using System.IO;

namespace UACServer
{
    public enum LogType
    {
        Info,
        Warning,
        Error,
        Detection,
        Auth, // dark green
        Proxy, // Green
        HashCheck, // Cyan
        Database, // Blue
        Heartbeat, // Yellow
        Forward, // Magenta
        InfoTag // New: for [INFO] [DETECTION], [INFO] [DB], etc.
    }

    public class Logger
    {
        public static void Log(string logFilePath, string message)
        {
            Log(logFilePath, message, LogType.Info);
        }

        public static void Log(string logFilePath, string message, LogType type)
        {
            string timestampString = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string prefix = GetPrefix(type);
            ConsoleColor color = GetColor(type);
            string full_msg = $"[{timestampString}] {prefix}{message}";
            lock (logLock)
            {
                var oldColor = Console.ForegroundColor;
                Console.ForegroundColor = color;
                Console.WriteLine(full_msg);
                Console.ForegroundColor = oldColor;
            }
            LogToFile(logFilePath, full_msg);
        }

        // Helper to log with Proxy color
        public static void LogProxy(string logFilePath, string message)
        {
            Log(logFilePath, message, LogType.Proxy);
        }

        // Helper to log with custom color
        public static void LogHashCheck(string logFilePath, string message)
        {
            Log(logFilePath, message, LogType.HashCheck);
        }
        public static void LogDatabase(string logFilePath, string message)
        {
            Log(logFilePath, message, LogType.Database);
        }
        public static void LogHeartbeat(string logFilePath, string message)
        {
            Log(logFilePath, message, LogType.Heartbeat);
        }
        public static void LogForward(string logFilePath, string message)
        {
            Log(logFilePath, message, LogType.Forward);
        }

        public static void LogInfoTag(string logFilePath, string message)
        {
            Log(logFilePath, message, LogType.InfoTag);
        }

        // Helper to log with Detection color
        public static void LogDetection(string logFilePath, string message)
        {
            Log(logFilePath, message, LogType.Detection);
        }

        public static void LogError(string logFilePath, string message)
        {
            Log(logFilePath, message, LogType.Error);
        }

        public static void LogAuth(string logFilePath, string message)
        {
            Log(logFilePath, message, LogType.Auth);
        }

        private static string GetPrefix(LogType type)
        {
            switch (type)
            {
                case LogType.Info:
                    return "[INFO] ";
                case LogType.Warning:
                    return "[WARNING] ⚠ "; // Orange/yellow warning sign
                case LogType.Error:
                    return "[ERROR] ! "; // Red exclamation
                case LogType.Detection:
                    return "[DETECTION] * "; // Magenta asterisk
                case LogType.Auth:
                    return "[AUTH] * ";
                case LogType.Proxy:
                    return "[PROXY] "; // Green for proxy
                case LogType.HashCheck:
                    return "[HASH_CHECK] ";
                case LogType.Database:
                    return "[DB] ";
                case LogType.Heartbeat:
                    return "[HEARTBEAT] ";
                case LogType.Forward:
                    return "[FORWARD] ";
                case LogType.InfoTag:
                    return "[INFO] "; // Keep [INFO] prefix for tag lines
                default:
                    return "";
            }
        }

        private static ConsoleColor GetColor(LogType type)
        {
            switch (type)
            {
                case LogType.Info:
                    return ConsoleColor.White; // Info: white
                case LogType.Warning:
                    return ConsoleColor.DarkYellow; // Warning: orange/yellow
                case LogType.Error:
                    return ConsoleColor.Red; // Error: red
                case LogType.Detection:
                    return ConsoleColor.Magenta; // Detection: magenta
                case LogType.Auth:
                    return ConsoleColor.DarkGreen; // Auth: dark green
                case LogType.Proxy:
                    return ConsoleColor.Green; // Proxy: green
                case LogType.HashCheck:
                    return ConsoleColor.Cyan; // HashCheck: cyan
                case LogType.Database:
                    return ConsoleColor.Blue; // Database: blue
                case LogType.Heartbeat:
                    return ConsoleColor.Yellow; // Heartbeat: yellow
                case LogType.Forward:
                    return ConsoleColor.DarkCyan; // Forward: dark cyan
                case LogType.InfoTag:
                    return ConsoleColor.Cyan; // Use Cyan or another visible color for info tags
                default:
                    return ConsoleColor.Gray;
            }
        }

        private static readonly object logLock = new object();
        public static void LogToFile(string logFilePath, string message)
        {
            lock (logLock)
            {
                try
                {
                    using (StreamWriter writer = new StreamWriter(logFilePath, true))
                    {
                        writer.WriteLine($"{message}");
                    }
                }
                catch (Exception ex)
                {
                    var oldColor = Console.ForegroundColor;
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Error writing to log file: {ex.Message}");
                    Console.ForegroundColor = oldColor;
                }
            }
        }
    }
}
