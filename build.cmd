@echo off
setlocal
if not exist build mkdir build
cl /nologo /W4 /WX /TC /Iinclude src\*.c /Fe:build\wintriage.exe
exit /b %errorlevel%
