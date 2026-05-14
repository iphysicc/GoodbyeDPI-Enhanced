@ECHO OFF
PUSHD "%~dp0"
start "" goodbyedpi.exe -9 --dns-addr 9.9.9.9 --dns-port 9953
POPD
