@echo off
REM Script per creare una Special patch .patch con 7-Zip secondo specifiche Duff
REM Il nome della patch è fisso: special.patch

set PATCHFILE=special.patch

REM Elimina la patch se esiste già
if exist "%PATCHFILE%" (
    del /f /q "%PATCHFILE%"
    echo Patch precedente "%PATCHFILE%" eliminata.
)

REM Escludi questo script e Updater.exe dal pacchetto
"C:\Program Files\7-Zip\7z.exe" a "%PATCHFILE%" .\* -tzip -mx=9 -mm=Deflate -mmt=on -r -y -x!crea_special_patch.bat -x!Updater.exe

if %errorlevel% equ 0 (
    echo Patch Special creata con successo: %PATCHFILE%
) else (
    echo Errore nella creazione della Special patch!
)