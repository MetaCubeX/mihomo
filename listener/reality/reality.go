package reality

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/metacubex/mihomo/listener/inner"
	"github.com/metacubex/mihomo/ntp"

	"github.com/sagernet/reality"
)

type Conn = reality.Conn

type Config struct {
	Dest              string
	PrivateKey        string
	ShortID           []string
	ServerNames       []string
	MaxTimeDifference int
	Proxy             string
}

func (c Config) Build() (*Builder, error) {
	realityConfig := &reality.Config{}
	realityConfig.SessionTicketsDisabled = true
	realityConfig.Type = "tcp"
	realityConfig.Dest = c.Dest
	realityConfig.Time = ntp.Now
	realityConfig.ServerNames = make(map[string]bool)
	for _, it := range c.ServerNames {
		realityConfig.ServerNames[it] = true
	}
	privateKey, err := base64.RawURLEncoding.DecodeString(c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(privateKey) != 32 {
		return nil, errors.New("invalid private key")
	}
	realityConfig.PrivateKey = privateKey

	realityConfig.MaxTimeDiff = time.Duration(c.MaxTimeDifference) * time.Microsecond

	realityConfig.ShortIds = make(map[[8]byte]bool)
	for i, shortIDString := range c.ShortID {
		var shortID [8]byte
		decodedLen, err := hex.Decode(shortID[:], []byte(shortIDString))
		if err != nil {
			return nil, fmt.Errorf("decode short_id[%d] '%s': %w", i, shortIDString, err)
		}
		if decodedLen > 8 {
			return nil, fmt.Errorf("invalid short_id[%d]: %s", i, shortIDString)
		}
		realityConfig.ShortIds[shortID] = true
	}

	realityConfig.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return inner.HandleTcp(address, c.Proxy)
	}

	return &Builder{realityConfig}, nil
}

type Builder struct {
	realityConfig *reality.Config
}

func (b Builder) NewListener(l net.Listener) net.Listener {
	l = reality.NewListener(l, b.realityConfig)
	// Due to low implementation quality, the reality server intercepted half close and caused memory leaks.
	// We fixed it by calling Close() directly.
	l = realityListenerWrapper{l}
	return l
}

type realityConnWrapper struct {
	*reality.Conn
}

func (c realityConnWrapper) Upstream() any {
	return c.Conn
}

func (c realityConnWrapper) CloseWrite() error {
	return c.Close()
}

type realityListenerWrapper struct {
	net.Listener
}

func (l realityListenerWrapper) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return realityConnWrapper{c.(*reality.Conn)}, nil
}
