$now = Get-Date -Format "yy,MM,dd,HH"
$rcFile = "UltimateAnticheat.rc"
$dotNow = $now -replace ",", "."

if ((Get-Item $rcFile).IsReadOnly) {
    (Get-Item $rcFile).IsReadOnly = $false
}

$lines = Get-Content $rcFile

for ($i = 0; $i -lt $lines.Count; $i++) {
    $clean = $lines[$i] -replace '^[\x00-\x20\x7F-\xA0]+', ''
    if ($clean -match '^FILEVERSION\s+\d+,\d+,\d+,\d+') {
        $lines[$i] = "FILEVERSION $now"
    }
    elseif ($clean -match '^PRODUCTVERSION\s+\d+,\d+,\d+,\d+') {
        $lines[$i] = "PRODUCTVERSION $now"
    }
    elseif ($clean -match 'VALUE "FileVersion",\s*"\d+\.\d+\.\d+\.\d+"') {
        $lines[$i] = 'VALUE "FileVersion", "' + $dotNow + '"'
    }
    elseif ($clean -match 'VALUE "ProductVersion",\s*"\d+\.\d+\.\d+\.\d+"') {
        $lines[$i] = 'VALUE "ProductVersion", "' + $dotNow + '"'
    }
}

function Write-SafeFile {
    param(
        [string]$Path,
        [string[]]$Lines
    )
    $tmp = "$Path.tmp"
    try {
        $Lines | Set-Content $tmp -Encoding Default
        Move-Item -Force $tmp $Path
        Write-Host "$Path version updated to $now"
    } catch {
        Write-Host ("[ERROR] Impossibile aggiornare {0}: {1}" -f $Path, $error[0])
        if (Test-Path $tmp) { Remove-Item $tmp -Force }
        exit 1
    }
}

Write-SafeFile $rcFile $lines