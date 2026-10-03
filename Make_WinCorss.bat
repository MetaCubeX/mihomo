@ECHO OFF && CHCP 65001 && CLS
setlocal EnableExtensions

cd /d "%~dp0"

set "NAME=mihomo"
set "BINDIR=bin"
set "TAGS=with_gvisor"
set "CGO_ENABLED=0"

if not exist "%BINDIR%" mkdir "%BINDIR%"
if not defined GOCACHE set "GOCACHE=%CD%\.gocache"
if not defined GOTMPDIR set "GOTMPDIR=%CD%\.gotmp"
if not exist "%GOCACHE%" mkdir "%GOCACHE%"
if not exist "%GOTMPDIR%" mkdir "%GOTMPDIR%"
if exist "%CD%\.gopath" set "GOPATH=%CD%\.gopath"

for /f "delims=" %%i in ('git branch --show-current 2^>nul') do set "BRANCH=%%i"

if /i "%BRANCH%"=="Alpha" (
    for /f "delims=" %%i in ('git rev-parse --short HEAD 2^>nul') do set "VERSION=alpha-%%i"
) else if /i "%BRANCH%"=="Beta" (
    for /f "delims=" %%i in ('git rev-parse --short HEAD 2^>nul') do set "VERSION=beta-%%i"
) else if "%BRANCH%"=="" (
    for /f "delims=" %%i in ('git describe --tags 2^>nul') do set "VERSION=%%i"
) else (
    for /f "delims=" %%i in ('git rev-parse --short HEAD 2^>nul') do set "VERSION=%%i"
)

if "%VERSION%"=="" set "VERSION=unknown"

for /f "delims=" %%i in ('powershell -NoProfile -Command "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)" 2^>nul') do set "BUILDTIME=%%i"
if "%BUILDTIME%"=="" set "BUILDTIME=unknown"

set "LDFLAGS=-X github.com/metacubex/mihomo/constant.Version=%VERSION% -X github.com/metacubex/mihomo/constant.BuildTime=%BUILDTIME% -w -s -buildid="

if "%~1"=="" (
    call :build linux-amd64-v3
    if errorlevel 1 exit /b 1
    call :build linux-arm64
    if errorlevel 1 exit /b 1
    call :build darwin-amd64-v3
    if errorlevel 1 exit /b 1
    call :build darwin-arm64
    if errorlevel 1 exit /b 1
    call :build windows-amd64-v3
    if errorlevel 1 exit /b 1
    call :build windows-arm64
    if errorlevel 1 exit /b 1
    goto :done
)

if /i "%~1"=="help" goto :help
if /i "%~1"=="-h" goto :help
if /i "%~1"=="--help" goto :help

if /i "%~1"=="all" (
    call "%~f0"
    exit /b %errorlevel%
)

if /i "%~1"=="windows" (
    call :build windows-amd64-compatible
    if errorlevel 1 exit /b 1
    call :build windows-amd64
    if errorlevel 1 exit /b 1
    call :build windows-amd64-v1
    if errorlevel 1 exit /b 1
    call :build windows-amd64-v2
    if errorlevel 1 exit /b 1
    call :build windows-amd64-v3
    if errorlevel 1 exit /b 1
    call :build windows-arm64
    if errorlevel 1 exit /b 1
    goto :done
)

if /i "%~1"=="all-arch" (
    for %%t in (
        darwin-amd64-compatible darwin-amd64 darwin-amd64-v1 darwin-amd64-v2 darwin-amd64-v3 darwin-arm64
        linux-386 linux-amd64-compatible linux-amd64 linux-amd64-v1 linux-amd64-v2 linux-amd64-v3 linux-armv5 linux-armv6 linux-armv7 linux-arm64
        linux-mips64 linux-mips64le linux-mips-softfloat linux-mips-hardfloat linux-mipsle-softfloat linux-mipsle-hardfloat linux-riscv64 linux-loong64
        android-arm64 freebsd-386 freebsd-amd64 freebsd-arm64
        windows-amd64-compatible windows-amd64 windows-amd64-v1 windows-amd64-v2 windows-amd64-v3 windows-arm64
    ) do (
        call :build %%t
        if errorlevel 1 exit /b 1
    )
    goto :done
)

:targets
if "%~1"=="" goto :done
call :build "%~1"
if errorlevel 1 exit /b 1
shift
goto :targets

:build
set "TARGET=%~1"
set "GOOS="
set "GOARCH="
set "GOAMD64="
set "GOARM="
set "GOMIPS="
set "EXT="

if /i "%TARGET%"=="darwin-amd64-compatible" set "GOOS=darwin" & set "GOARCH=amd64" & set "GOAMD64=v1"
if /i "%TARGET%"=="darwin-amd64" set "GOOS=darwin" & set "GOARCH=amd64" & set "GOAMD64=v3"
if /i "%TARGET%"=="darwin-amd64-v1" set "GOOS=darwin" & set "GOARCH=amd64" & set "GOAMD64=v1"
if /i "%TARGET%"=="darwin-amd64-v2" set "GOOS=darwin" & set "GOARCH=amd64" & set "GOAMD64=v2"
if /i "%TARGET%"=="darwin-amd64-v3" set "GOOS=darwin" & set "GOARCH=amd64" & set "GOAMD64=v3"
if /i "%TARGET%"=="darwin-arm64" set "GOOS=darwin" & set "GOARCH=arm64"

if /i "%TARGET%"=="linux-386" set "GOOS=linux" & set "GOARCH=386"
if /i "%TARGET%"=="linux-amd64-compatible" set "GOOS=linux" & set "GOARCH=amd64" & set "GOAMD64=v1"
if /i "%TARGET%"=="linux-amd64" set "GOOS=linux" & set "GOARCH=amd64" & set "GOAMD64=v3"
if /i "%TARGET%"=="linux-amd64-v1" set "GOOS=linux" & set "GOARCH=amd64" & set "GOAMD64=v1"
if /i "%TARGET%"=="linux-amd64-v2" set "GOOS=linux" & set "GOARCH=amd64" & set "GOAMD64=v2"
if /i "%TARGET%"=="linux-amd64-v3" set "GOOS=linux" & set "GOARCH=amd64" & set "GOAMD64=v3"
if /i "%TARGET%"=="linux-arm64" set "GOOS=linux" & set "GOARCH=arm64"
if /i "%TARGET%"=="linux-armv5" set "GOOS=linux" & set "GOARCH=arm" & set "GOARM=5"
if /i "%TARGET%"=="linux-armv6" set "GOOS=linux" & set "GOARCH=arm" & set "GOARM=6"
if /i "%TARGET%"=="linux-armv7" set "GOOS=linux" & set "GOARCH=arm" & set "GOARM=7"
if /i "%TARGET%"=="linux-mips-softfloat" set "GOOS=linux" & set "GOARCH=mips" & set "GOMIPS=softfloat"
if /i "%TARGET%"=="linux-mips-hardfloat" set "GOOS=linux" & set "GOARCH=mips" & set "GOMIPS=hardfloat"
if /i "%TARGET%"=="linux-mipsle-softfloat" set "GOOS=linux" & set "GOARCH=mipsle" & set "GOMIPS=softfloat"
if /i "%TARGET%"=="linux-mipsle-hardfloat" set "GOOS=linux" & set "GOARCH=mipsle" & set "GOMIPS=hardfloat"
if /i "%TARGET%"=="linux-mips64" set "GOOS=linux" & set "GOARCH=mips64"
if /i "%TARGET%"=="linux-mips64le" set "GOOS=linux" & set "GOARCH=mips64le"
if /i "%TARGET%"=="linux-riscv64" set "GOOS=linux" & set "GOARCH=riscv64"
if /i "%TARGET%"=="linux-loong64" set "GOOS=linux" & set "GOARCH=loong64"

if /i "%TARGET%"=="android-arm64" set "GOOS=android" & set "GOARCH=arm64"

if /i "%TARGET%"=="freebsd-386" set "GOOS=freebsd" & set "GOARCH=386"
if /i "%TARGET%"=="freebsd-amd64" set "GOOS=freebsd" & set "GOARCH=amd64" & set "GOAMD64=v3"
if /i "%TARGET%"=="freebsd-arm64" set "GOOS=freebsd" & set "GOARCH=arm64"

if /i "%TARGET%"=="windows-amd64-compatible" set "GOOS=windows" & set "GOARCH=amd64" & set "GOAMD64=v1" & set "EXT=.exe"
if /i "%TARGET%"=="windows-amd64" set "GOOS=windows" & set "GOARCH=amd64" & set "GOAMD64=v3" & set "EXT=.exe"
if /i "%TARGET%"=="windows-amd64-v1" set "GOOS=windows" & set "GOARCH=amd64" & set "GOAMD64=v1" & set "EXT=.exe"
if /i "%TARGET%"=="windows-amd64-v2" set "GOOS=windows" & set "GOARCH=amd64" & set "GOAMD64=v2" & set "EXT=.exe"
if /i "%TARGET%"=="windows-amd64-v3" set "GOOS=windows" & set "GOARCH=amd64" & set "GOAMD64=v3" & set "EXT=.exe"
if /i "%TARGET%"=="windows-arm64" set "GOOS=windows" & set "GOARCH=arm64" & set "EXT=.exe"

if "%GOOS%"=="" (
    echo Unknown target: %TARGET%
    echo.
    goto :help
)

echo Building %NAME%-%TARGET%%EXT%  VERSION=%VERSION%
go build -tags "%TAGS%" -trimpath -ldflags "%LDFLAGS%" -o "%BINDIR%\%NAME%-%TARGET%%EXT%" .
exit /b %errorlevel%

:done
echo Done.
exit /b 0

:help
echo Usage:
echo   Make_WinCorss.bat                 Build the same default targets as Makefile all
echo   Make_WinCorss.bat windows         Build all Windows targets
echo   Make_WinCorss.bat all-arch        Build every Makefile platform target
echo   Make_WinCorss.bat TARGET [...]    Build one or more explicit targets
echo.
echo Examples:
echo   Make_WinCorss.bat linux-amd64-v3 windows-arm64
echo   Make_WinCorss.bat windows
exit /b 1
