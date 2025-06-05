//UltimateAnticheat Server - By AlSch092 @ Github
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace UACServer
{
    public class AntiCheatClient
    {
        public int id; //unique id

        public IPAddress ip_addr;

        public bool flagged_cheater = false;

        public string hardware_id;
        public string hostname;
        public string mac_address;
        public string gamecode; //each game gets its own unique code

        private bool authorized = false;
        private bool heartbeat_received = false;
        public int current_heartbeat_count = 0;

        public List<string> heartbeat_responses;

        public int time_connected;
        public int connected_at; //tickcount representation of time

        public TcpClient net_client = null;

        public bool in_heartbeat_loop = false;
        public bool gracefulDisconnect = false;
        public DateTime? LastHeartbeatLog { get; set; }
        // Aggiunto per controllo hash periodico
        public DateTime LastHashCheckTime { get; set; } = DateTime.UtcNow;
        public AntiCheatClient()
        {
            heartbeat_responses = new List<string>();
        }
    }
}
