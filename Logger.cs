//UltimateAnticheat Server - By AlSch092 @ Github
using System;
using System.IO;

namespace UACServer
{
    public class Logger
    {
        public static void Log(string logFilePath, string message)
        {
            string timestampString = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string full_msg = "[" + timestampString + "] " + message ;
            Console.WriteLine(full_msg);
            LogToFile(logFilePath, full_msg);
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
                    Console.WriteLine($"Error writing to log file: {ex.Message}");
                }
            }
        }
    }
}
