@echo off
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
python -m PyInstaller --onefile --uac-admin --name AION2_OathEnergy --collect-submodules scapy aion2_live_monitor.py
if errorlevel 1 goto :error

echo.
echo ===================================================
echo Done! dist\AION2_OathEnergy.exe has been created.
echo Share just that one exe file - nothing else is needed.
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
