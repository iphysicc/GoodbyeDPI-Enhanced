@ECHO OFF
PUSHD "%~dp0"
sc stop GoodbyeDPI
sc delete GoodbyeDPI
echo.
echo Service stopped and removed.
pause
POPD
