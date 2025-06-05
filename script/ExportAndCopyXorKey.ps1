# Esegui il tool per generare la chiave
& "$PSScriptRoot\ExportXorKeyTool.exe"

# Copia la chiave dove serve
$source = "$PSScriptRoot\xor_key.txt"
$dest = "$PSScriptRoot\..\UltimateAntiCheat-Server\bin\Release\xor_key.txt"

if (Test-Path $source) {
    Copy-Item -Path $source -Destination $dest -Force
    Write-Host "xor_key.txt copiato in $dest"
} else {
    Write-Host "ATTENZIONE: xor_key.txt non trovato in $source"
    exit 1
}
