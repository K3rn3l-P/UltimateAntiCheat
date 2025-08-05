$now = Get-Date -Format "yy,MM,dd,HH"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$csFile = Join-Path $scriptDir "..\UltimateAntiCheat-Server\Properties\AssemblyInfo.cs"
$programFile = Join-Path $scriptDir "..\UltimateAntiCheat-Server\Program.cs"
$dotNow = $now -replace ",", "."
$verString = "v$dotNow"

function Write-SafeFile {
    param(
        [string]$Path,
        [string]$Content
    )
    $tmp = "$Path.tmp"
    $Content | Set-Content $tmp -Encoding UTF8
    Move-Item -Force $tmp $Path
}

# Aggiorna AssemblyInfo.cs
$content = Get-Content $csFile -Raw

# Aggiorna tutte le occorrenze di AssemblyVersion e AssemblyFileVersion
$content = [regex]::Replace($content, 'AssemblyVersion\("\d+\.\d+\.\d+\.\d+"\)', "AssemblyVersion(`"$dotNow`")", "IgnoreCase")
$content = [regex]::Replace($content, 'AssemblyFileVersion\("\d+\.\d+\.\d+\.\d+"\)', "AssemblyFileVersion(`"$dotNow`")", "IgnoreCase")
Write-SafeFile $csFile $content
Write-Host "AssemblyInfo.cs version updated to $now"

# Aggiorna Program.cs
if (Test-Path $programFile) {
    $progContent = Get-Content $programFile -Raw
    $progContent = [regex]::Replace($progContent, 'const string current_ver = ".*?";', "const string current_ver = `"$verString`";", "IgnoreCase")
    Write-SafeFile $programFile $progContent
    Write-Host "Program.cs current_ver updated to $verString"
} else {
    Write-Host "Program.cs non trovato: $programFile"
}