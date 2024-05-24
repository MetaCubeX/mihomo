package service

import (
	"flag"
	"fmt"
	S "github.com/kardianos/service"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

var Srv S.Service
var Prg *Program
var ServiceName = "clash"

type Program struct {
	Run func()
}

func (p *Program) Start(s S.Service) error {
	// Start should not block. Do the actual work async.
	go p.run()
	return nil
}

func (p *Program) run() {
	// Do work here
	p.Run()
}
func (p *Program) Stop(s S.Service) error {
	// Stop should not block. Return with a few seconds.
	return nil
}

func NewService(Run func()) *Program {
	svcConfig := &S.Config{
		Name:        ServiceName,
		DisplayName: ServiceName,
		Description: ServiceName,
	}
	Prg = &Program{Run: Run}
	var err error
	Srv, err = S.New(Prg, svcConfig)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if IsOpenWrt() {
		svcConfig.Option = S.KeyValue{}
		svcConfig.Option["SysvScript"] = openWrtScript
	}
	fmt.Println("platform", Srv.Platform())
	return Prg
}

func (p *Program) Action(action string) {
	var err error
	switch action {
	case "install":
		err := Srv.Install()
		if err != nil {
			fmt.Println(err)
			return
		}
		if IsOpenWrt() {
			// On OpenWrt it is important to run enable after the service installation
			// Otherwise, the service won't start on the system startup
			_, err := runInitdCommand("enable")
			if err != nil {
				fmt.Println(err)
			}
			return
		}
	case "uninstall":
		if IsOpenWrt() {
			// On OpenWrt it is important to run disable command first
			// as it will remove the symlink
			_, err := runInitdCommand("disable")
			if err != nil {
				fmt.Println(err)
				return
			}
		}
		err = Srv.Uninstall()
		if err != nil {
			fmt.Println(err)
		}
	case "status":
		status, err := Srv.Status()
		if err != nil {
			if IsOpenWrt() {
				status = 0
			} else {
				fmt.Println(err)
				return
			}
		}
		switch status {
		case 0:
			fmt.Printf("unknown\n")
		case 1:
			fmt.Printf("running\n")
		case 2:
			fmt.Printf("stopped\n")
		}
	case "start":
		fallthrough
	case "stop":
		fallthrough
	case "restart":
		err := S.Control(Srv, action)
		if err != nil {
			if IsOpenWrt() {
				_, err := runInitdCommand(action)
				if err != nil {
					fmt.Println(1, err)
				}
			} else {
				fmt.Println(2, err)
			}
		}
	default:
		flag.PrintDefaults()
	}
}

func (p *Program) RunIt() {
	status, _ := Srv.Status()
	if status != S.StatusUnknown {
		// if installed as service, it always goes here.
		err := Srv.Run()
		if err != nil {
			fmt.Println(err)
		}
	} else {
		// this makes use of running directly otherwise.
		p.Run()
	}
}

// IsOpenWrt checks if OS is OpenWRT
func IsOpenWrt() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	body, err := ioutil.ReadFile("/etc/os-release")
	if err != nil {
		return false
	}
	return strings.Contains(string(body), "OpenWrt")
}

// runInitdCommand runs init.d service command
// returns command code or error if any
func runInitdCommand(action string) (int, error) {
	confPath := "/etc/init.d/" + ServiceName
	code, _, err := RunCommand("sh", "-c", confPath+" "+action)
	return code, err
}

// runCommand runs shell command
func RunCommand(command string, arguments ...string) (int, string, error) {
	cmd := exec.Command(command, arguments...)
	out, err := cmd.Output()
	if err != nil {
		return 1, "", fmt.Errorf("exec.Command(%s) failed: %v: %s", command, err, string(out))
	}

	return cmd.ProcessState.ExitCode(), string(out), nil
}

// OpenWrt procd init script
// https://github.com/AdguardTeam/AdGuardHome/issues/1386
const openWrtScript = `#!/bin/sh /etc/rc.common
DESCRIPTION="{{.Name}}"
cmd="{{.Path}}{{range .Arguments}} {{.|cmd}}{{end}}"
name="{{.Name}}"
pid_file="/var/run/$name.pid"
stdout_log="/var/log/$name.log"
stderr_log="/var/log/$name.err"
START=99
get_pid() {
    cat "$pid_file"
}
is_running() {
    [ -f "$pid_file" ] && cat /proc/$(get_pid)/stat > /dev/null 2>&1
}
start() {
        if is_running; then
                echo "Already started"
        else
                echo "Starting $name"

                $cmd >> "$stdout_log" 2>> "$stderr_log" &
                echo $! > "$pid_file"
                if ! is_running; then
                        echo "Unable to start, see $stdout_log and $stderr_log"
                        exit 1
                fi
        fi
}
stop() {
        if is_running; then
                echo -n "Stopping $name.."
                kill $(get_pid)
                for i in $(seq 1 10)
                do
                        if ! is_running; then
                                break
                        fi
                        echo -n "."
                        sleep 1
                done
                echo
                if is_running; then
                        echo "Not stopped; may still be shutting down or shutdown may have failed"
                        exit 1
                else
                        echo "Stopped"
                        if [ -f "$pid_file" ]; then
                                rm "$pid_file"
                        fi
                fi
        else
                echo "Not running"
        fi
}
restart() {
        stop
        if is_running; then
                echo "Unable to stop, will not attempt to start"
                exit 1
        fi
        start
}
status() {
    if is_running; then
        echo "Running"
    else
        echo "Stopped"
        exit 1
    fi
}
`
