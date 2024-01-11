package service

import (
	"github.com/kardianos/service"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"os"
	"path/filepath"
)

type program struct{}

var (
	SvcConfig      *service.Config
	Program        *program
	SysService     service.Service
	Elevated       bool
	mainFunc       func()
	Noninteractive bool
)

func Init(runFunc func()) (service.Status, error) {
	Elevated = isAdmin()
	mainFunc = runFunc
	Noninteractive = false

	err := error(nil)
	svcHomeDir, err := filepath.Abs(C.Path.HomeDir())
	SvcConfig = &service.Config{
		Name:        "mihomo-kernel",
		DisplayName: "Mihomo Kernel",
		Description: "Another Mihomo Kernel.",
		Arguments: []string{
			"--service", "noninteractive",
			"-d", svcHomeDir,
		},
		//Dependencies: []string{
		//	"Requires=network.target",
		//	"After=network-online.target"},
		Option: service.KeyValue{
			"Restart":           "on-success",
			"SuccessExitStatus": "1 2 8 SIGKILL",
		},
	}

	Program = &program{}
	SysService, err = service.New(Program, SvcConfig)
	if err != nil {
		log.Errorln("Fatal: %s", err)
		os.Exit(1)
	}
	return SysService.Status()
}

func SetLogger(fileDir string) {
	filePath := filepath.Join(fileDir, "service.log")

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0777)
	if err != nil {
		os.Stdout = f
		os.Stderr = f
	}
}

func actionLog(action string, err error) {
	if err == nil {
		log.Infoln("Successfully to %s a service.", action)
		return
	}

	if !Elevated {
		log.Errorln("Service control action needs elevated privileges. Please run with administrator privileges.")
	}
	log.Errorln("Failed to %s a service: %s", action, err)

}
