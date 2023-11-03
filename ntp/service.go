package ntp

import (
	"context"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	"github.com/metacubex/mihomo/log"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/ntp"
)

var offset time.Duration
var service *Service

type Service struct {
	server         M.Socksaddr
	dialer         proxydialer.SingDialer
	ticker         *time.Ticker
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	syncSystemTime bool
	running        bool
}

func ReCreateNTPService(server string, interval time.Duration, dialerProxy string, syncSystemTime bool) {
	if service != nil {
		service.Stop()
	}
	ctx, cancel := context.WithCancel(context.Background())
	service = &Service{
		server:         M.ParseSocksaddr(server),
		dialer:         proxydialer.NewByNameSingDialer(dialerProxy, dialer.NewDialer()),
		ticker:         time.NewTicker(interval * time.Minute),
		ctx:            ctx,
		cancel:         cancel,
		syncSystemTime: syncSystemTime,
	}
	service.Start()
}

func (srv *Service) Start() {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	log.Infoln("NTP service start, sync system time is %t", srv.syncSystemTime)
	service.running = true
	srv.update()
	go srv.loopUpdate()
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

func (srv *Service) update() {
	var response *ntp.Response
	var err error
	for i := 0; i < 3; i++ {
		response, err = ntp.Exchange(context.Background(), srv.dialer, srv.server)
		if err != nil {
			if i == 2 {
				log.Errorln("Initialize NTP time failed: %s", err)
				return
			}
			time.Sleep(time.Second * 2) // wait for 2 seconds before the next try
			continue
		}
		break
	}
	offset = response.ClockOffset
	if offset > time.Duration(0) {
		log.Infoln("System clock is ahead of NTP time by %s", offset)
	} else if offset < time.Duration(0) {
		log.Infoln("System clock is behind NTP time by %s", -offset)
	}
	if srv.syncSystemTime {
		timeNow := response.Time
		err = setSystemTime(timeNow)
		if err == nil {
			log.Infoln("Sync system time success: %s", timeNow.Local().Format(ntp.TimeLayout))
		} else {
			log.Errorln("Write time to system: %s", err)
			srv.syncSystemTime = false
		}
	}
}

func (srv *Service) loopUpdate() {
	for {
		select {
		case <-srv.ctx.Done():
			return
		case <-srv.ticker.C:
		}
		srv.update()
	}
}

func Now() time.Time {
	now := time.Now()
	if service.Running() && offset.Abs() > 0 {
		now = now.Add(offset)
	}
	return now
}
