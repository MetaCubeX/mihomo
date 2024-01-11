package service

import (
	"github.com/kardianos/service"
	"github.com/metacubex/mihomo/hub/executor"
	"os"
)

func (p *program) Start(s service.Service) error {
	// Start should not block. Do the actual work async.
	go mainFunc()
	return nil
}

//
//func (p *program) run() {
//	// Do work here
//
//}

func (p *program) Stop(s service.Service) error {
	// Stop should not block. Return with a few seconds.
	go p.exit()
	return nil
}

func (p *program) exit() {
	executor.Shutdown()
	os.Exit(0)
}
