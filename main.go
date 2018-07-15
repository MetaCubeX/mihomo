package main

import (
	"os"
	"os/signal"
	"syscall"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/hub"
	"github.com/Dreamacro/clash/proxy"
	"github.com/Dreamacro/clash/tunnel"

	log "github.com/sirupsen/logrus"
)

func main() {
	if err := tunnel.GetInstance().UpdateConfig(); err != nil {
		log.Fatalf("Parse config error: %s", err.Error())
	}

	if err := proxy.Instance().Run(); err != nil {
		log.Fatalf("Proxy listen error: %s", err.Error())
	}

	// Hub
	cfg, err := C.GetConfig()
	if err != nil {
		log.Fatalf("Read config error: %s", err.Error())
	}

	section := cfg.Section("General")
	if key, err := section.GetKey("external-controller"); err == nil {
		go hub.NewHub(key.Value())
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
