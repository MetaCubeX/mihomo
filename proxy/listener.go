package proxy

import (
	"sync"

	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/proxy/http"
	"github.com/Dreamacro/clash/proxy/redir"
	"github.com/Dreamacro/clash/proxy/socks"
)

var (
	listener *Listener
	once     sync.Once
)

type Listener struct {
	// signal for update
	httpSignal  *C.ProxySignal
	socksSignal *C.ProxySignal
	redirSignal *C.ProxySignal
}

func (l *Listener) updateHTTP(addr string) error {
	if l.httpSignal != nil {
		signal := l.httpSignal
		signal.Done <- struct{}{}
		<-signal.Closed
		l.httpSignal = nil
	}

	signal, err := http.NewHttpProxy(addr)
	if err != nil {
		return err
	}

	l.httpSignal = signal
	return nil
}

func (l *Listener) updateSocks(addr string) error {
	if l.socksSignal != nil {
		signal := l.socksSignal
		signal.Done <- struct{}{}
		<-signal.Closed
		l.socksSignal = nil
	}

	signal, err := socks.NewSocksProxy(addr)
	if err != nil {
		return err
	}

	l.socksSignal = signal
	return nil
}

func (l *Listener) updateRedir(addr string) error {
	if l.redirSignal != nil {
		signal := l.redirSignal
		signal.Done <- struct{}{}
		<-signal.Closed
		l.redirSignal = nil
	}

	signal, err := redir.NewRedirProxy(addr)
	if err != nil {
		return err
	}

	l.redirSignal = signal
	return nil
}

func (l *Listener) process(signal chan<- struct{}) {
	sub := config.Instance().Subscribe()
	signal <- struct{}{}
	reportCH := config.Instance().Report()
	for elm := range sub {
		event := elm.(*config.Event)
		switch event.Type {
		case "http-addr":
			addr := event.Payload.(string)
			err := l.updateHTTP(addr)
			reportCH <- &config.Event{Type: "http-addr", Payload: err == nil}
			break
		case "socks-addr":
			addr := event.Payload.(string)
			err := l.updateSocks(addr)
			reportCH <- &config.Event{Type: "socks-addr", Payload: err == nil}
			break
		case "redir-addr":
			addr := event.Payload.(string)
			err := l.updateRedir(addr)
			reportCH <- &config.Event{Type: "redir-addr", Payload: err == nil}
			break
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
