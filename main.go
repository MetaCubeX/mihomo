package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/Dreamacro/clash/config"
	"github.com/Dreamacro/clash/hub"
	"github.com/Dreamacro/clash/proxy"
	"github.com/Dreamacro/clash/tunnel"

	log "github.com/sirupsen/logrus"
)

func main() {
	tunnel.Instance().Run()
	proxy.Instance().Run()
	hub.Run()

	config.Init()
	err := config.Instance().Parse()
	if err != nil {
		log.Fatalf("Parse config error: %s", err.Error())
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
