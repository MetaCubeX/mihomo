ECHO %date:~0,4%-%date:~5,2%-%date:~8,2% %time:~0,2%:%time:~3,2%:%time:~6,2%
set RELEASE=%date:~0,4%-%date:~5,2%-%date:~8,2% %time:~0,2%:%time:~3,2%:%time:~6,2%
ECHO %RELEASE%
set GOOS=linux
set CGO_ENABLED=0
set GOARCH=arm64

go build -o clash -trimpath  -ldflags="-X 'github.com/metacubex/mihomo/constant.Version=%RELEASE%' -X 'github.com/metacubex/mihomo/constant.BuildTime=%RELEASE%' -w -s" ..