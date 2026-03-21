package reality

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inner"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"

	utls "github.com/metacubex/utls"
)

type Conn = utls.Conn
type LimitFallback = utls.RealityLimitFallback

type Config struct {
	Dest              string
	PrivateKey        string
	ShortID           []string
	ServerNames       []string
	MaxTimeDifference int
	Proxy             string

	LimitFallbackUpload   LimitFallback
	LimitFallbackDownload LimitFallback
}

func (c Config) Build(tunnel C.Tunnel) (*Builder, error) {
	realityConfig := &utls.RealityConfig{}
	realityConfig.SessionTicketsDisabled = true
	realityConfig.Type = "tcp"
	realityConfig.Dest = c.Dest
	realityConfig.Time = ntp.Now
	realityConfig.ServerNames = make(map[string]bool)
	realityConfig.Log = log.Debugln
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
		decodedLen := hex.DecodedLen(len(shortIDString))
		if decodedLen > 8 {
			return nil, fmt.Errorf("invalid short_id[%d]: %s", i, shortIDString)
		}
		decodedLen, err = hex.Decode(shortID[:], []byte(shortIDString))
		if err != nil {
			return nil, fmt.Errorf("decode short_id[%d] '%s': %w", i, shortIDString, err)
		}
		if decodedLen > 8 {
			return nil, fmt.Errorf("invalid short_id[%d]: %s", i, shortIDString)
		}
		realityConfig.ShortIds[shortID] = true
	}

	realityConfig.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return inner.HandleTcp(tunnel, address, c.Proxy)
	}

	realityConfig.LimitFallbackUpload = c.LimitFallbackUpload
	realityConfig.LimitFallbackDownload = c.LimitFallbackDownload

	return &Builder{realityConfig}, nil
}

type Builder struct {
	realityConfig *utls.RealityConfig
}

func (b Builder) NewListener(l net.Listener) net.Listener {
	return N.NewHandleContextListener(context.Background(), l, func(ctx context.Context, conn net.Conn) (net.Conn, error) {
		c, err := utls.RealityServer(ctx, conn, b.realityConfig)
		if err != nil {
			return nil, err
		}
		// Due to low implementation quality, the reality server intercepted half-close and caused memory leaks.
		// We fixed it by calling Close() directly.
		return realityConnWrapper{c}, nil
	}, func(a any) {
		stack := debug.Stack()
		log.Errorln("reality server panic: %s\n%s", a, stack)
	})
}

type realityConnWrapper struct {
	*utls.Conn
}

func (c realityConnWrapper) Upstream() any {
	return c.Conn
}

func (c realityConnWrapper) CloseWrite() error {
	return c.Close()
}

func (c realityConnWrapper) ReaderReplaceable() bool {
	return true
}

func (c realityConnWrapper) WriterReplaceable() bool {
	return true
}
