using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace UACServer.Network
{
    public class BlacklistManager
    {
        private static readonly string RemoteUrl = "https://raw.githubusercontent.com/AlSch092/UltimateAntiCheat/refs/heads/main/MiscFiles/BlacklistedProcessList.txt";
        private static readonly string LocalPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Config", "BlacklistedProcessList.local.txt");
        private static readonly string ConfigDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Config");
        private static readonly TimeSpan RemoteUpdateInterval = TimeSpan.FromMinutes(10);
        private static readonly object _lock = new object();

        private static List<string> _processes = new List<string>();
        private static List<string> _keywords = new List<string>();
        private static DateTime _lastRemoteUpdate = DateTime.MinValue;
        private static FileSystemWatcher _watcher;
        private static Thread _remoteUpdateThread;
        private static bool _running = false;

        public static IReadOnlyList<string> BlacklistedProcesses { get { lock (_lock) { return _processes.AsReadOnly(); } } }
        public static IReadOnlyList<string> BlacklistedKeywords { get { lock (_lock) { return _keywords.AsReadOnly(); } } }

        public static void Start()
        {
            if (!Directory.Exists(ConfigDir))
                Directory.CreateDirectory(ConfigDir);
            if (!File.Exists(LocalPath))
            {
                File.WriteAllText(LocalPath, "# Add one process name per line.\n# For keywords, use: KEYWORD: keyword\n# Example:\ncheatengine.exe\nKEYWORD: hack\n");
            }
            LoadLocal();
            LoadRemote().Wait();
            _running = true;
            _remoteUpdateThread = new Thread(RemoteUpdateLoop) { IsBackground = true };
            _remoteUpdateThread.Start();
            _watcher = new FileSystemWatcher(ConfigDir, Path.GetFileName(LocalPath));
            _watcher.Changed += (s, e) => LoadLocal();
            _watcher.Created += (s, e) => LoadLocal();
            _watcher.EnableRaisingEvents = true;
        }

        private static void RemoteUpdateLoop()
        {
            while (_running)
            {
                try
                {
                    if ((DateTime.UtcNow - _lastRemoteUpdate) > RemoteUpdateInterval)
                    {
                        LoadRemote().Wait();
                        _lastRemoteUpdate = DateTime.UtcNow;
                    }
                }
                catch { }
                Thread.Sleep(60000);
            }
        }

        private static void LoadLocal()
        {
            lock (_lock)
            {
                var localProcesses = new List<string>();
                var localKeywords = new List<string>();
                if (File.Exists(LocalPath))
                {
                    foreach (var line in File.ReadAllLines(LocalPath))
                    {
                        var l = line.Trim();
                        if (string.IsNullOrEmpty(l) || l.StartsWith("#")) continue;
                        if (l.StartsWith("KEYWORD:", StringComparison.OrdinalIgnoreCase))
                        {
                            var kw = l.Substring(8).Trim();
                            if (!string.IsNullOrEmpty(kw)) localKeywords.Add(kw);
                        }
                        else
                        {
                            localProcesses.Add(l);
                        }
                    }
                }
                // Merge with remote (if already loaded)
                foreach (var p in _processes)
                    if (!localProcesses.Contains(p)) localProcesses.Add(p);
                foreach (var k in _keywords)
                    if (!localKeywords.Contains(k)) localKeywords.Add(k);
                _processes = localProcesses;
                _keywords = localKeywords;
            }
        }

        private static async Task LoadRemote()
        {
            try
            {
                using (var http = new HttpClient())
                {
                    var txt = await http.GetStringAsync(RemoteUrl);
                    var remoteProcesses = new List<string>();
                    var remoteKeywords = new List<string>();
                    using (var reader = new StringReader(txt))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            var l = line.Trim();
                            if (string.IsNullOrEmpty(l) || l.StartsWith("#")) continue;
                            if (l.StartsWith("KEYWORD:", StringComparison.OrdinalIgnoreCase))
                            {
                                var kw = l.Substring(8).Trim();
                                if (!string.IsNullOrEmpty(kw)) remoteKeywords.Add(kw);
                            }
                            else
                            {
                                remoteProcesses.Add(l);
                            }
                        }
                    }
                    lock (_lock)
                    {
                        _processes = remoteProcesses;
                        _keywords = remoteKeywords;
                    }
                }
            }
            catch { }
        }
    }
}
