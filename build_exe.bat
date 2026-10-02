@echo off
setlocal
cd /d "%~dp0"
echo === AION2 Oath Energy Monitor - exe build ===
echo Run this from the project folder.
echo.

python -m pip install --upgrade pip
if errorlevel 1 goto :error

python -m pip install -r requirements.txt
if errorlevel 1 goto :error

echo.
echo Building... (this can take a few minutes)
echo.

rem --uac-admin : the exe will auto-prompt for admin rights (UAC) on launch
rem --onefile   : bundle everything into a single exe
rem --collect-submodules scapy : scapy uses dynamic imports internally, so grab everything to avoid missing-module errors
rem Use a fresh intermediate directory to avoid stale/locked PYZ files.
set "AION2_BUILD_WORK=%TEMP%\AION2_build_%RANDOM%_%RANDOM%"
python -m PyInstaller --workpath "%AION2_BUILD_WORK%" --distpath "%~dp0dist" AION2_OathEnergy.spec
if errorlevel 1 goto :error

echo.
echo ===================================================
echo Done! dist\AION2_OathEnergy.exe has been created.
echo Share just that one exe file - nothing else is needed.
echo Logs are appended to logs\AION2_YYYY-MM-DD.txt next to the exe.
echo (Npcap must already be installed on the machine that runs it,
echo  and you must click "Yes" on the admin-rights prompt each run.)
echo ===================================================
pause
exit /b 0

:error
echo.
echo Build failed. Check the error message above.
pause
exit /b 1
