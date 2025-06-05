//UltimateAnticheat Server - By AlSch092 @ Github

namespace UACServer.Network.Opcodes
{
    public enum CS //client2server
    {
        CS_HELLO = 1,
        CS_GOODBYE, //there is no SC_GOODBYE
        CS_HEARTBEAT,
        CS_INFO_LOGGING, //hostname + mac address + hardware ID
        CS_FLAGGED_CHEATER,
        CS_QUERY_MEMORY,
        CS_HASH_CHECK, // <--- AGGIUNGI QUESTO
        CS_CLIENTINFO_PERIODIC // <--- AGGIUNTO PER INVIO PERIODICO INFO CLIENT
    };

    public enum SC //server2client
    {
        SC_HELLO = 1,
        SC_HEARTBEAT,
        SC_INFO_LOGGING,
        SC_FLAGGED_CHEATER,
        SC_QUERY_MEMORY,
        SC_HASH_CHECK_RESULT, // <--- AGGIUNGI QUESTO (opzionale)
    };
}