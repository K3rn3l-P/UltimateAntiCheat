# KeyGen.ps1

Write-Host "== Step 1: Generazione chiave privata RSA (PKCS#1) =="
openssl genrsa -out private.pem 2048
Write-Host "private.pem generata."
Write-Host ""

Write-Host "== Step 2: Forza riscrittura in PKCS#1 (se necessario) =="
openssl rsa -in private.pem -out private_rsa.pem -traditional
Write-Host "private_rsa.pem generata."
Write-Host ""

Write-Host "== Step 3: Sovrascrivi private.pem con la versione PKCS#1 =="
mv -Force private_rsa.pem private.pem
Write-Host "private.pem sovrascritta."
Write-Host ""

Write-Host "== Step 4: Estrai la chiave pubblica PKCS#1 (PEM) =="
openssl rsa -in private.pem -RSAPublicKey_out -out public.pem
Write-Host "public.pem generata."
Write-Host ""

Write-Host "== Step 5: Firma un file di test (data.txt) =="
echo Hello > data.txt
openssl dgst -sha256 -sign private.pem -out sig.bin data.txt
Write-Host "File data.txt firmato, sig.bin generato."
Write-Host ""

Write-Host "== Step 6: Verifica la firma appena creata =="
openssl dgst -sha256 -verify public.pem -signature sig.bin data.txt
Write-Host ""

Write-Host "== Step 7: Estrai la chiave pubblica PKCS#1 in DER (per il client) =="
openssl rsa -in private.pem -RSAPublicKey_out -outform DER -out public.der
Write-Host "public.der generata."
Write-Host ""

Write-Host "== Step 8: Genera file binario di test (data.bin) con 4 byte 01 00 64 00 =="
[byte[]] $bytes = 0x01,0x00,0x64,0x00
[System.IO.File]::WriteAllBytes("data.bin", $bytes)
Write-Host "data.bin generato."
Write-Host ""

Write-Host "== Step 9: Firma data.bin con la chiave privata =="
openssl dgst -sha256 -sign private.pem -out sig.bin data.bin
Write-Host "data.bin firmato, sig.bin generato."
Write-Host ""

Write-Host "== Step 10: Verifica la firma di data.bin =="
openssl dgst -sha256 -verify public.pem -signature sig.bin data.bin
Write-Host ""

Write-Host "== Riepilogo file generati =="
Get-ChildItem -Path . -Include private.pem,public.pem,public.der,data.txt,data.bin,sig.bin | Format-Table Name,Length,LastWriteTime

Write-Host ""
Write-Host "Chiavi generate! Usa solo private.pem (server) e public.der (client)."
pause

Write-Host "== Debug: verifica la chiave pubblica =="
openssl rsa -in private.pem -RSAPublicKey_out -text -noout
openssl rsa -pubin -in public.pem -text -noout

pause
