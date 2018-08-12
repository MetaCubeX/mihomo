package http

import (
	"bufio"
	"net"
	"net/http"
	"strings"

	"github.com/Dreamacro/clash/adapters/local"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/tunnel"

	log "github.com/sirupsen/logrus"
)

var (
	tun = tunnel.Instance()
)

func NewHttpProxy(addr string) (*C.ProxySignal, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	done := make(chan struct{})
	closed := make(chan struct{})
	signal := &C.ProxySignal{
		Done:   done,
		Closed: closed,
	}

	go func() {
		log.Infof("HTTP proxy listening at: %s", addr)
		for {
			c, err := l.Accept()
			if err != nil {
				if _, open := <-done; !open {
					break
				}
				continue
			}
			go handleConn(c)
		}
	}()

	go func() {
		<-done
		close(done)
		l.Close()
		closed <- struct{}{}
	}()

	return signal, nil
}

func handleConn(conn net.Conn) {
	br := bufio.NewReader(conn)
	method, hostName := adapters.ParserHTTPHostHeader(br)
	if hostName == "" {
		return
	}

	if !strings.Contains(hostName, ":") {
		hostName += ":80"
	}

	var peeked []byte
	if method == http.MethodConnect {
		_, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		if err != nil {
			return
		}
	} else if n := br.Buffered(); n > 0 {
		peeked, _ = br.Peek(br.Buffered())
	}

	tun.Add(adapters.NewHTTP(hostName, peeked, method != http.MethodConnect, conn))
}
