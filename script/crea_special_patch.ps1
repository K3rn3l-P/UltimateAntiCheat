$ErrorActionPreference = "Stop"
trap { Write-Host "ERRORE: $($_.Exception.Message)"; exit 1 }

$hashDir = Join-Path $PSScriptRoot "..\UltimateAntiCheat-Server\bin\Release\hash"
$patchFile = Join-Path $hashDir "special.patch"
$sevenZip = "C:\Program Files\7-Zip\7z.exe"

if (!(Test-Path $sevenZip)) {
    Write-Host "ERRORE: 7-Zip non trovato in $sevenZip"
    exit 1
}
if (!(Test-Path $hashDir)) {
    Write-Host "ERRORE: Cartella hash non trovata: $hashDir"
    exit 1
}

# Escludi sia Updater.exe che special.patch dalla lista dei file da includere
$files = Get-ChildItem -Path $hashDir -File | Where-Object { $_.Name -ne "Updater.exe" -and $_.Name -ne "special.patch" }
if ($files.Count -eq 0) {
    Write-Host "ERRORE: Nessun file da includere nella patch."
    exit 1
}

Write-Host "File inclusi nella patch:"
$files | ForEach-Object { Write-Host " - $($_.Name)" }

# Cancella la patch precedente se esiste
if (Test-Path $patchFile) {
    Remove-Item $patchFile -Force
    Write-Host "Patch precedente '$patchFile' eliminata."
}

# Crea la patch
& "$sevenZip" a "$patchFile" $($files | ForEach-Object { "`"$($_.FullName)`"" }) -tzip -mx=9 -mm=Deflate -mmt=on -y

if ($LASTEXITCODE -eq 0) {
    Write-Host "Patch Special creata con successo: $patchFile"
} else {
    Write-Host "ERRORE: Errore nella creazione della Special patch!"
    exit 1
}