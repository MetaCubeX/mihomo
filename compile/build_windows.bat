ECHO %date:~0,4%-%date:~5,2%-%date:~8,2% %time:~0,2%:%time:~3,2%:%time:~6,2%
set RELEASE=%date:~0,4%-%date:~5,2%-%date:~8,2% %time:~0,2%:%time:~3,2%:%time:~6,2%
ECHO %RELEASE%

set GOOS=windows
set CGO_ENABLED=0
set GOARCH=amd64
set GOAMD64=v3
go build -o meta.exe -trimpath  -ldflags="-X 'github.com/metacubex/mihomo/constant.Version=%RELEASE%' -X 'github.com/metacubex/mihomo/constant.BuildTime=%RELEASE%' -w -s" ..