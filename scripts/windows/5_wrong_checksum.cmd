@ECHO OFF
PUSHD "%~dp0"
start "" goodbyedpi.exe -7 --dns-addr 9.9.9.9 --dns-port 9953
POPD
