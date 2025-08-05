# 1. Prepara le variabili
$hashSource = "C:\Users\lol1\Documents\A-Best-Installation-GUIDE\100.Code-Project\UltimateAntiCheat\UltimateAntiCheat-Server\bin\Release\hash"
$patchSpecialDir = "C:\Users\lol1\Documents\A-Best-Installation-GUIDE\100.Code-Project\UltimateAntiCheat\script\Duff-tool\patch\special"
$duffToolDir = "C:\Users\lol1\Documents\A-Best-Installation-GUIDE\100.Code-Project\UltimateAntiCheat\script\Duff-tool"
$patchFile = "$duffToolDir\patch\special.patch"
$destPatchFile = "$hashSource\special.patch"

# 2. Assicurati che la cartella di destinazione esista e sia vuota
if (Test-Path $patchSpecialDir) { Remove-Item "$patchSpecialDir\*" -Recurse -Force }
else { New-Item -ItemType Directory -Path $patchSpecialDir | Out-Null }

# 3. Copia i file hash nella cartella patch/special
Copy-Item "$hashSource\*" $patchSpecialDir -Recurse -Force

# 4. Esegui il comando Duff-Tool.exe patch special
Push-Location $duffToolDir
& .\Duff-Tool.exe patch special
Pop-Location

# 5. Copia la patch generata nella cartella hash di bin\Release
Copy-Item $patchFile $destPatchFile -Force