package proxy

import (
	"fmt"
	"sync"

	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/proxy/http"
	"github.com/Dreamacro/clash/proxy/socks"
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

func (l *Listener) Update(base *config.Base) error {
	if base.AllowLan != nil {
		l.allowLan = *base.AllowLan
	}

	var socksErr, httpErr error
	if base.AllowLan != nil || base.Port != nil {
		newHTTPPort := l.httpPort
		if base.Port != nil {
			newHTTPPort = *base.Port
		}
		httpErr = l.updateHTTP(newHTTPPort)
	}

	if base.AllowLan != nil || base.SocketPort != nil {
		newSocksPort := l.socksPort
		if base.SocketPort != nil {
			newSocksPort = *base.SocketPort
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

func (l *Listener) process(signal chan<- struct{}) {
	sub := config.Instance().Subscribe()
	signal <- struct{}{}
	for elm := range sub {
		event := elm.(*config.Event)
		if event.Type == "base" {
			base := event.Payload.(config.Base)
			l.Update(&base)
		}
	}
}

// Run ensure config monitoring
func (l *Listener) Run() {
	signal := make(chan struct{})
	go l.process(signal)
	<-signal
}

func newListener() *Listener {
	return &Listener{}
}

// Instance return singleton instance of Listener
func Instance() *Listener {
	once.Do(func() {
		listener = newListener()
	})
	return listener
}
