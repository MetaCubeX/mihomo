package proxy

import (
	"fmt"
	"net"
	"strconv"

	"github.com/Dreamacro/clash/proxy/http"
	"github.com/Dreamacro/clash/proxy/redir"
	"github.com/Dreamacro/clash/proxy/socks"
)

var (
	allowLan = false

	socksListener *listener
	httpListener  *listener
	redirListener *listener
)

type listener struct {
	Address string
	Done    chan<- struct{}
	Closed  <-chan struct{}
}

type Ports struct {
	Port      int `json:"port"`
	SocksPort int `json:"socks-port"`
	RedirPort int `json:"redir-port"`
}

func AllowLan() bool {
	return allowLan
}

func SetAllowLan(al bool) {
	allowLan = al
}

func ReCreateHTTP(port int) error {
	addr := genAddr(port, allowLan)

	if httpListener != nil {
		if httpListener.Address == addr {
			return nil
		}
		httpListener.Done <- struct{}{}
		<-httpListener.Closed
		httpListener = nil
	}

	if portIsZero(addr) {
		return nil
	}

	done, closed, err := http.NewHttpProxy(addr)
	if err != nil {
		return err
	}

	httpListener = &listener{
		Address: addr,
		Done:    done,
		Closed:  closed,
	}
	return nil
}

func ReCreateSocks(port int) error {
	addr := genAddr(port, allowLan)

	if socksListener != nil {
		if socksListener.Address == addr {
			return nil
		}
		socksListener.Done <- struct{}{}
		<-socksListener.Closed
		socksListener = nil
	}

	if portIsZero(addr) {
		return nil
	}

	done, closed, err := socks.NewSocksProxy(addr)
	if err != nil {
		return err
	}

	socksListener = &listener{
		Address: addr,
		Done:    done,
		Closed:  closed,
	}
	return nil
}

func ReCreateRedir(port int) error {
	addr := genAddr(port, allowLan)

	if redirListener != nil {
		if redirListener.Address == addr {
			return nil
		}
		redirListener.Done <- struct{}{}
		<-redirListener.Closed
		redirListener = nil
	}

	if portIsZero(addr) {
		return nil
	}

	done, closed, err := redir.NewRedirProxy(addr)
	if err != nil {
		return err
	}

	redirListener = &listener{
		Address: addr,
		Done:    done,
		Closed:  closed,
	}
	return nil
}

// GetPorts return the ports of proxy servers
func GetPorts() *Ports {
	ports := &Ports{}

	if httpListener != nil {
		_, portStr, _ := net.SplitHostPort(httpListener.Address)
		port, _ := strconv.Atoi(portStr)
		ports.Port = port
	}

	if socksListener != nil {
		_, portStr, _ := net.SplitHostPort(socksListener.Address)
		port, _ := strconv.Atoi(portStr)
		ports.SocksPort = port
	}

	if redirListener != nil {
		_, portStr, _ := net.SplitHostPort(redirListener.Address)
		port, _ := strconv.Atoi(portStr)
		ports.RedirPort = port
	}

	return ports
}

func portIsZero(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	if port == "0" || port == "" || err != nil {
		return true
	}
	return false
}

func genAddr(port int, allowLan bool) string {
	if allowLan {
		return fmt.Sprintf(":%d", port)
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
}
