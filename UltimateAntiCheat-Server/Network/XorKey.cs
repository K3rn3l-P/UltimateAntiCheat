using System;
using System.Security.Cryptography;
using System.Text;

public static class CryptoUtils
{
    public static string DecryptGameCode(string encryptedBase64)
    {
        var encryptedBytes = Convert.FromBase64String(encryptedBase64);
        using (var rsa = new RSACryptoServiceProvider())
        {
            // Carica la chiave privata XML
            string privateKeyXml = System.IO.File.ReadAllText("private_key.xml");
            rsa.FromXmlString(privateKeyXml);
            var decryptedBytes = rsa.Decrypt(encryptedBytes, true); // true = OAEP
            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}
