# Script per progetto DAC Ultimate AntiCheat!
$ErrorActionPreference = "Stop"

# Log file path (modifica se vuoi salvarlo altrove)
$logFile = "C:\Users\lol1\Documents\A-Best-Installation-GUIDE\100.Code-Project\UltimateAntiCheat\postbuild_hash_update.log"
function Write-Log($msg) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp $msg" | Out-File -FilePath $logFile -Append
    Write-Host $msg
}

trap {
    Write-Log "[ERRORE] Si è verificato un errore nello script: $($_.Exception.Message)"
    pause
    exit 1
}

Write-Log "=== Post-build hash update started ==="

# Percorsi dei file da controllare
$files = @{
    "Updater.exe" = "C:\Users\lol1\Documents\A-Best-Installation-GUIDE\100.Code-Project\shaiya-updater\Updater\bin\Release\net6.0-windows7.0\publish\win-x86\Updater.exe"
    "duff.dll"    = "C:\Users\lol1\Documents\A-Best-Installation-GUIDE\100.Code-Project\shaiya-essentials\Release\duff.dll"
    "x32.exe"     = "C:\Users\lol1\Documents\A-Best-Installation-GUIDE\100.Code-Project\Duff_Client-v20\x32.exe"
    "game.exe"    = "C:\Users\lol1\Documents\A-Best-Installation-GUIDE\100.Code-Project\UltimateAntiCheat\x64\Release\game.exe"
}

# Calcola gli hash
$hashes = @{}
$missing = @()
foreach ($key in $files.Keys) {
    if (Test-Path $files[$key]) {
        $hash = (Get-FileHash -Path $files[$key] -Algorithm SHA256).Hash.ToUpper()
        $hashes[$key] = $hash
        Write-Log "$($key): $hash"
    } else {
        Write-Log "File non trovato: $($files[$key])"
        $missing += $key
    }
}
# Controllo: tutti gli hash devono essere trovati
if ($missing.Count -gt 0) {
    Write-Log "Errore: Mancano i seguenti file, impossibile aggiornare sha256_hashes.hpp e ExpectedHashes.cs:"
    $missing | ForEach-Object { Write-Log " - $_" }
    pause
    exit 1
}

# Percorso al file header da aggiornare
$headerPath = "C:\Users\lol1\Documents\A-Best-Installation-GUIDE\100.Code-Project\UltimateAntiCheat\Common\sha256_hashes.hpp"

# Genera il contenuto del file header
$headerContent = @"
#pragma once
#include <string>

const std::string expectedUpdaterSha256 = "$($hashes['Updater.exe'])";
const std::string expectedDuffDllSha256 = "$($hashes['duff.dll'])";
const std::string expectedX32Sha256 = "$($hashes['x32.exe'])";
const std::string expectedDACSha256 = "$($hashes['game.exe'])";

"@

# Scrivi il file header
$headerContent | Set-Content $headerPath -Encoding UTF8
Write-Log "SHA256 aggiornati in sha256_hashes.hpp"

# Percorso al file C# da aggiornare
$csPath = "C:\Users\lol1\Documents\A-Best-Installation-GUIDE\100.Code-Project\UltimateAntiCheat\UltimateAntiCheat-Server\Network\ExpectedHashes.cs"

# Genera il contenuto del file C#
$csContent = @"
namespace UACServer.Network
{
    public static class ExpectedHashes
    {
        public const string Updater = ""$($hashes['Updater.exe'])"";
        public const string DuffDll = ""$($hashes['duff.dll'])"";
        public const string X32Exe = ""$($hashes['x32.exe'])"";
        public const string DAC = ""$($hashes['game.exe'])"";
    }
}
"@ -replace '""', '"'

# Scrivi il file C#
$csContent | Set-Content $csPath -Encoding UTF8
Write-Log "SHA256 aggiornati in ExpectedHashes.cs"

# Verifica post-scrittura degli hash
try {
    $headerRead = Get-Content $headerPath -Raw
    foreach ($k in @('Updater.exe','duff.dll','x32.exe','game.exe')) {
        if ($headerRead -notmatch $hashes[$k]) {
            Write-Log "[ERRORE] Verifica post-scrittura fallita su sha256_hashes.hpp per $k"
            throw "Verifica post-scrittura fallita su sha256_hashes.hpp per $k"
        }
    }
    $csRead = Get-Content $csPath -Raw
    foreach ($k in @('Updater.exe','duff.dll','x32.exe','game.exe')) {
        if ($csRead -notmatch $hashes[$k]) {
            Write-Log "[ERRORE] Verifica post-scrittura fallita su ExpectedHashes.cs per $k"
            throw "Verifica post-scrittura fallita su ExpectedHashes.cs per $k"
        }
    }
    Write-Log "[SUCCESS] Tutti i file hash sono stati aggiornati e verificati correttamente."
} catch {
    Write-Log "[FATAL] Errore durante la verifica finale: $_"
    pause
    exit 1
}

# Copia i file necessari nella cartella di destinazione
$destFolder = "C:\Users\lol1\Documents\A-Best-Installation-GUIDE\100.Code-Project\Duff_Client-v20"
$toCopy = @("Updater.exe", "duff.dll", "game.exe")

foreach ($key in $toCopy) {
    $src = $files[$key]
    $dest = Join-Path $destFolder $key
    if (Test-Path $src) {
        try {
            Copy-Item -Path $src -Destination $dest -Force
            Write-Log "Copiato $key in $dest"
        } catch {
            Write-Log "Errore nella copia di ${key}: $($error[0].Exception.Message)"
        }
    } else {
        Write-Log "Non trovato (non copiato): $src"
    }
}

# Copia i file necessari nella cartella hash della release del server
$serverReleaseDir = "C:\Users\lol1\Documents\A-Best-Installation-GUIDE\100.Code-Project\UltimateAntiCheat\UltimateAntiCheat-Server\bin\Release"
$hashDir = Join-Path $serverReleaseDir "hash"
if (-not (Test-Path $hashDir)) {
    New-Item -ItemType Directory -Path $hashDir | Out-Null
    Write-Log "Creata cartella: $hashDir"
}
$toCopyHash = @("x32.exe", "Updater.exe", "duff.dll", "game.exe")
foreach ($key in $toCopyHash) {
    $src = $files[$key]
    $dest = Join-Path $hashDir $key
    if (Test-Path $src) {
        try {
            Copy-Item -Path $src -Destination $dest -Force
            Write-Log "Copiato $key in $dest"
        } catch {
            Write-Log "Errore nella copia di ${key}: $($_.Exception.Message)"
        }
    } else {
        Write-Log "Non trovato (non copiato): $src"
    }
}

Write-Log "=== Post-build hash update completed ==="
Write-Host "`nTutto OK! Hash e file aggiornati correttamente." -ForegroundColor Green
pause