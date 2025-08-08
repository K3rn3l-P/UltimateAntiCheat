using System;
using System.Threading;
using UACServer.Network;
using System.IO;

namespace UACServer
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // --- All'avvio: sposta special.patch se esiste ---
            string exeDir = AppDomain.CurrentDomain.BaseDirectory;
            string hashDir = Path.Combine(exeDir, "hash");
            string patchSrc = Path.Combine(hashDir, "special.patch");
            string patchDst = @"C:\xampp\htdocs\shaiya\patch\special.patch";
            try
            {
                if (File.Exists(patchSrc))
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(patchDst));
                    if (File.Exists(patchDst))
                        File.Delete(patchDst); // sovrascrivi se già presente
                    File.Move(patchSrc, patchDst);
                    Logger.Log("DACServer.log", $"[INIT] Spostata special.patch in {patchDst} (ad ogni avvio se presente)");
                }
            }
            catch (Exception ex)
            {
                Logger.Log("DACServer.log", $"[ERROR] Errore spostamento special.patch: {ex}");
            }

            AppDomain.CurrentDomain.UnhandledException += (sender, e) =>
            {
                Exception ex = e.ExceptionObject as Exception;
                Logger.Log("DACServer.log", "[FATAL] Unhandled exception: " + ex?.ToString());
            };

            const string listen_addr = "100.95.179.88";
            const int port = 5445;

            const string current_ver = "v25.08.08.16";

            Console.Title = "DUFF AntiCheat Server " + current_ver;

            // Avvia i proxy TCP per ps_login e ps_game
            var loginProxy = new TcpProxy("100.95.179.88", 30800, "127.0.0.1", 58423);
            var loginThread = new Thread(loginProxy.Start) { IsBackground = true };
            loginThread.Start();

            var gameProxy = new TcpProxy("100.95.179.88", 30810, "100.95.179.88", 62547);
            var gameThread = new Thread(gameProxy.Start) { IsBackground = true };
            gameThread.Start();

            // Avvia il server anti-cheat come prima
            AnticheatServer server = new AnticheatServer();
            server.Start(listen_addr, port);

            Logger.Log("DACServer.log", "Server initialized: Press the Q key to stop the program...");

            bool listening_input = true;

            while (listening_input)
            {
                ConsoleKeyInfo key = Console.ReadKey();
                if (key.KeyChar == 'q')
                {
                    listening_input = false;
                    server.Stop();
                }
            }

            Logger.Log("DACServer.log", "Finished listening...");
        }
    }
}












































