package ntp

import (
	"context"
	"github.com/Dreamacro/clash/log"
	"github.com/beevik/ntp"
	"sync"
	"time"
)

var offset time.Duration
var service *Service

type Service struct {
	addr     string
	interval time.Duration
	ticker   *time.Ticker
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	running  bool
}

func ReCreateNTPService(addr string, interval time.Duration) {
	if service != nil {
		service.Stop()
	}
	ctx, cancel := context.WithCancel(context.Background())
	service = &Service{addr: addr, interval: interval, ctx: ctx, cancel: cancel}
	service.Start()
}

func (srv *Service) Start() {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	log.Infoln("NTP service start")
	srv.ticker = time.NewTicker(srv.interval * time.Minute)
	service.running = true
	go func() {
		for {
			err := srv.updateTime(srv.addr)
			if err != nil {
				log.Warnln("updateTime failed: %s", err)
			}
			select {
			case <-srv.ticker.C:
			case <-srv.ctx.Done():
				return
			}
		}
	}()
}

func (srv *Service) Stop() {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if service.running {
		srv.ticker.Stop()
		srv.cancel()
		service.running = false
	}
}

func (srv *Service) Running() bool {
	if srv == nil {
		return false
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.running
}

func (srv *Service) updateTime(addr string) error {
	response, err := ntp.Query(addr)
	if err != nil {
		return err
	}
	localTime := time.Now()
	ntpTime := response.Time
	offset = localTime.Sub(ntpTime)
	if offset > time.Duration(0) {
		log.Warnln("System clock is ahead of NTP time by %s", offset)
	} else if offset < time.Duration(0) {
		log.Warnln("System clock is behind NTP time by %s", -offset)
	}
	return nil
}

func Now() time.Time {
	now := time.Now()
	if service.Running() && offset.Abs() > 0 {
		now = now.Add(offset)
	}
	return now
}
