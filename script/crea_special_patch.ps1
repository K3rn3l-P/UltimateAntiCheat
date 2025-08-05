# 1. Prepara le variabili
$hashSource = "C:\Users\lol1\Documents\A-Best-Installation-GUIDE\100.Code-Project\UltimateAntiCheat\UltimateAntiCheat-Server\bin\Release\hash"
$patchSpecialDir = "C:\Users\lol1\Documents\A-Best-Installation-GUIDE\100.Code-Project\UltimateAntiCheat\script\Duff-tool\patch\special"
$duffToolDir = "C:\Users\lol1\Documents\A-Best-Installation-GUIDE\100.Code-Project\UltimateAntiCheat\script\Duff-tool"
$patchFile = "$duffToolDir\patch\special.patch"
$destPatchFile = "$hashSource\special.patch"

# 2. Assicurati che la cartella di destinazione esista e sia vuota
if (Test-Path $patchSpecialDir) { Remove-Item "$patchSpecialDir\*" -Recurse -Force }
else { New-Item -ItemType Directory -Path $patchSpecialDir | Out-Null }

# 3. Copia SOLO i file richiesti nella cartella patch/special, blocca la build se mancano
$requiredFiles = @("duff.dll", "game.exe", "x32.exe")
$missing = @()
foreach ($file in $requiredFiles) {
    $src = Join-Path $hashSource $file
    if (Test-Path $src) {
        Copy-Item $src $patchSpecialDir -Force
    } else {
        $missing += $file
    }
}
if ($missing.Count -gt 0) {
    $missingList = $missing -join ', '
    Write-Error ('I seguenti file richiesti non sono stati trovati in ' + $hashSource + ': ' + $missingList)
    exit 1
}

# 4. Esegui il comando DuffToolCli.exe patch special
Push-Location $duffToolDir
& .\DuffToolCli.exe patch special
$exitCode = $LASTEXITCODE
Pop-Location

if ($exitCode -ne 0) {
    Write-Error ('DuffToolCli.exe patch special ha restituito un errore (' + $exitCode + ').')
    exit $exitCode
}

# 5. Copia la patch generata nella cartella hash di bin\Release
if (Test-Path $patchFile) {
    Copy-Item $patchFile $destPatchFile -Force
} else {
    Write-Error ('La patch non è stata generata: ' + $patchFile + ' non trovato.')
    exit 1
}