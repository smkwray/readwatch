@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "VERSION=%~1"
if "%VERSION%"=="" set "VERSION=0.3.0"

where go >nul 2>nul
if errorlevel 1 (
  echo Go was not found in PATH.
  exit /b 1
)

if not exist dist mkdir dist

echo [1/3] Tests
go test ./...
if errorlevel 1 exit /b 1

echo [2/3] Vet
go vet ./...
if errorlevel 1 exit /b 1

echo [3/3] Windows x64 release build
set "GOOS=windows"
set "GOARCH=amd64"
set "CGO_ENABLED=0"
go build -trimpath -ldflags "-s -w -H=windowsgui -X main.version=%VERSION%" -o dist\ReadWatch.exe .\cmd\readwatch
if errorlevel 1 exit /b 1

copy /y assets\ReadWatch.ico dist\ReadWatch.ico >nul
copy /y assets\ReadWatch.exe.manifest dist\ReadWatch.exe.manifest >nul

echo.
echo Built dist\ReadWatch.exe
certutil -hashfile dist\ReadWatch.exe SHA256
