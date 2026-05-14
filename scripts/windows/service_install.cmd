@ECHO OFF
PUSHD "%~dp0"
sc create "GoodbyeDPI" binPath= "\"%~dp0goodbyedpi.exe\" -9 --dns-addr 9.9.9.9 --dns-port 9953" start= auto
sc description "GoodbyeDPI" "GoodbyeDPI Enhanced - DPI circumvention utility"
sc start GoodbyeDPI
echo.
echo Service installed and started.
pause
POPD
