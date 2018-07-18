package proxy

import (
	"fmt"
	"sync"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/proxy/http"
	"github.com/Dreamacro/clash/proxy/socks"

	log "github.com/sirupsen/logrus"
)

var (
	listener *Listener
	once     sync.Once
)

type Listener struct {
	httpPort  int
	socksPort int
	allowLan  bool

	// signal for update
	httpSignal  *C.ProxySignal
	socksSignal *C.ProxySignal
}

// Info returns the proxies's current configuration
func (l *Listener) Info() (info C.General) {
	return C.General{
		Port:      &l.httpPort,
		SocksPort: &l.socksPort,
		AllowLan:  &l.allowLan,
	}
}

func (l *Listener) Update(allowLan *bool, httpPort *int, socksPort *int) error {
	if allowLan != nil {
		l.allowLan = *allowLan
	}

	var socksErr, httpErr error
	if allowLan != nil || httpPort != nil {
		newHTTPPort := l.httpPort
		if httpPort != nil {
			newHTTPPort = *httpPort
		}
		httpErr = l.updateHTTP(newHTTPPort)
	}

	if allowLan != nil || socksPort != nil {
		newSocksPort := l.socksPort
		if socksPort != nil {
			newSocksPort = *socksPort
		}
		socksErr = l.updateSocks(newSocksPort)
	}

	if socksErr != nil && httpErr != nil {
		return fmt.Errorf("%s\n%s", socksErr.Error(), httpErr.Error())
	} else if socksErr != nil {
		return socksErr
	} else if httpErr != nil {
		return httpErr
	} else {
		return nil
	}
}

func (l *Listener) updateHTTP(port int) error {
	if l.httpSignal != nil {
		signal := l.httpSignal
		signal.Done <- struct{}{}
		<-signal.Closed
		l.httpSignal = nil
	}

	signal, err := http.NewHttpProxy(l.genAddr(port))
	if err != nil {
		return err
	}

	l.httpSignal = signal
	l.httpPort = port
	return nil
}

func (l *Listener) updateSocks(port int) error {
	if l.socksSignal != nil {
		signal := l.socksSignal
		signal.Done <- struct{}{}
		<-signal.Closed
		l.socksSignal = nil
	}

	signal, err := socks.NewSocksProxy(l.genAddr(port))
	if err != nil {
		return err
	}

	l.socksSignal = signal
	l.socksPort = port
	return nil
}

func (l *Listener) genAddr(port int) string {
	host := "127.0.0.1"
	if l.allowLan {
		host = ""
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func (l *Listener) Run() error {
	return l.Update(&l.allowLan, &l.httpPort, &l.socksPort)
}

func newListener() *Listener {
	cfg, err := C.GetConfig()
	if err != nil {
		log.Fatalf("Read config error: %s", err.Error())
	}

	general := cfg.Section("General")

	port := general.Key("port").RangeInt(C.DefalutHTTPPort, 1, 65535)
	socksPort := general.Key("socks-port").RangeInt(C.DefalutSOCKSPort, 1, 65535)
	allowLan := general.Key("allow-lan").MustBool()

	return &Listener{
		httpPort:  port,
		socksPort: socksPort,
		allowLan:  allowLan,
	}
}

func Instance() *Listener {
	once.Do(func() {
		listener = newListener()
	})
	return listener
}
