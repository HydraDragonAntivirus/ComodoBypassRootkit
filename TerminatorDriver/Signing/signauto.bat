@echo off

:: Remove any existing signature from terminator.sys
signtool.exe remove /s "terminator.sys"

:: Sign the terminator.sys file with the PFX password
signtool.exe sign /f "UTKUDORUKBAYRAKTAR.pfx" /p "UTKUDORUKBAYRAKTAR" /fd SHA256 /t http://timestamp.digicert.com /a "terminator.sys"

echo Files signed successfully
pause
