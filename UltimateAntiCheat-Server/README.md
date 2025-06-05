# UltimateAntiCheat (SERVER): A server for UltimateAntiCheat built in C#

![ExampleOutput](https://github.com/AlSch092/UltimateAntiCheat/assets/94417808/8607553b-42b1-4bc4-ab1c-fa59d9eb4c8f)

## 🛠️ Post-Build pulita!

### 1. Post BUILD Client

if not exist "$(ProjectDir)x64\Release" mkdir "$(ProjectDir)x64\Release"
xcopy /Y /I "$(ProjectDir)splash.png" "$(ProjectDir)x64\Release\"
powershell -ExecutionPolicy Bypass -File "$(ProjectDir)script\sha256_hashes.ps1"
powershell -ExecutionPolicy Bypass -File "$(ProjectDir)script\ExportAndCopyXorKey.ps1"

### 2. Post BUILD Server (Eventi di Compilazione)

powershell -ExecutionPolicy Bypass -File "$(ProjectDir)..\script\sha256_hashes.ps1" && powershell -ExecutionPolicy Bypass -File "$(ProjectDir)..\script\ExportAndCopyXorKey.ps1"

---

---

## 🛠️ Build pulita da shell (CMake/MSBuild)

Ecco una mini-guida per risolvere problemi di build C++ con CMake/MSBuild:

### 1.0 Prova prima con questo!

```sh
rmdir /s /q x64\Release && rmdir /s /q Ultimate.344d69c4 && del /s /q *.obj *.pdb *.tlog *.idb *.ipch *.lastbuildstate *.log *.pch *.ilk *.exp *.res *.exe *.dll *.tmp *.cache 2>nul
```

```sh
del /s /q x64\Release\*.* && del /s /q Ultimate.344d69c4\*.* && del /s /q *.obj *.pdb *.tlog *.idb *.ipch *.lastbuildstate *.log *.pch *.ilk *.exp *.res *.exe *.dll *.tmp *.cache 2>nul
```

```sh
cmd /c "rmdir /s /q x64\Release && rmdir /s /q Ultimate.344d69c4 && del /s /q *.obj *.pdb *.tlog *.idb *.ipch *.lastbuildstate *.log *.pch *.ilk *.exp *.res *.exe *.dll *.tmp *.cache"
```

```sh
msbuild UltimateAnticheat.vcxproj /t:Rebuild /p:Configuration=Release /p:Platform=x64
```

Oppure:

```sh
msbuild UltimateAnticheat.vcxproj /t:Rebuild /p:Configuration=Release
```

### 1. Pulizia della cartella di build (opzionale ma consigliato)

```sh
rmdir build
mkdir build
cd build
```

### 2. Generazione dei file di progetto con CMake

```sh
cmake .. -G "Visual Studio 17 2022" -A x64
```

> Cambia il generatore se usi una versione diversa di Visual Studio.

### 3. Compilazione con MSBuild (o tramite CMake)

```sh
cmake --build . --config Release
```

oppure direttamente:

```sh
msbuild UltimateAnticheat.vcxproj /p:Configuration=Release
```

msbuild UltimateAnticheat.vcxproj /t:Rebuild /p:Configuration=Release

### 4. (Opzionale) Pulizia della soluzione Visual Studio

Se vuoi forzare una pulizia anche da Visual Studio:

```sh
msbuild UltimateAnticheat.vcxproj /t:Clean
```

### 5. RICORDATI IL FILE CMakeList.txt aggiornato!

---

## How to use:

Simply open & build the project using visual studio (originally made in VS2022), and allow the program through your private network firewall when the Windows prompt pops up. You can then run the UltimateAnticheat project (client) and it will attempt to connect to this server on port 5445.

## Requirements:

- Windows-based operating system
- Port 5445 must be unused (or this port changed in the `Program.cs` file

## Featurelist:

- Connected client tracking including hardware ID, remote IP, private network hostname
- Heartbeat mechanism every 60 seconds (in-progress)

## Notice:

A premium version of this software exists which has been load tested and has built-in MySql or MSSQL database integration, along with improved readability, more detection features; thus this public version may be considered 'lacking' in various ways. The license fee is generally quite affordable and helps towards my basic living expenses. Please send me an e-mail if you're interested!
