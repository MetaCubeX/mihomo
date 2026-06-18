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
	proxyproto "github.com/pires/go-proxyproto"
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
	ProxyProtocol     int

	LimitFallbackUpload   LimitFallback
	LimitFallbackDownload LimitFallback
}

func (c Config) Build(tunnel C.Tunnel) (*Builder, error) {
	if c.ProxyProtocol < 0 || c.ProxyProtocol > 2 {
		return nil, fmt.Errorf("invalid proxy-protocol version: %d", c.ProxyProtocol)
	}

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
		target, err := inner.HandleTcp(tunnel, address, c.Proxy)
		if err != nil {
			return nil, err
		}
		if err := writeProxyProtocolHeader(ctx, target, c.ProxyProtocol); err != nil {
			_ = target.Close()
			return nil, err
		}
		return target, nil
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
		ctx = context.WithValue(ctx, sourceAddrContextKey{}, conn.RemoteAddr())
		ctx = context.WithValue(ctx, destinationAddrContextKey{}, conn.LocalAddr())
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

type sourceAddrContextKey struct{}

type destinationAddrContextKey struct{}

func writeProxyProtocolHeader(ctx context.Context, conn net.Conn, version int) error {
	switch version {
	case 0:
		return nil
	case 1, 2:
	default:
		return fmt.Errorf("invalid proxy-protocol version: %d", version)
	}

	sourceAddr, destinationAddr := sourceAndDestinationAddrsFromContext(ctx)
	header, degraded := buildProxyProtocolHeader(byte(version), sourceAddr, destinationAddr)
	if degraded {
		log.Warnln("REALITY proxy-protocol degraded to UNKNOWN/LOCAL for source=%T(%v) destination=%T(%v)", sourceAddr, sourceAddr, destinationAddr, destinationAddr)
	}
	_, err := header.WriteTo(conn)
	if err != nil {
		return fmt.Errorf("write proxy-protocol header: %w", err)
	}
	return nil
}

func sourceAndDestinationAddrsFromContext(ctx context.Context) (net.Addr, net.Addr) {
	sourceAddr, _ := ctx.Value(sourceAddrContextKey{}).(net.Addr)
	destinationAddr, _ := ctx.Value(destinationAddrContextKey{}).(net.Addr)
	return sourceAddr, destinationAddr
}

func buildProxyProtocolHeader(version byte, sourceAddr, destinationAddr net.Addr) (*proxyproto.Header, bool) {
	sourceTCPAddr, destinationTCPAddr, ok := proxyProtocolTCPAddrPair(sourceAddr, destinationAddr)
	if !ok {
		return unknownProxyProtocolHeader(version), true
	}

	return proxyproto.HeaderProxyFromAddrs(version, sourceTCPAddr, destinationTCPAddr), false
}

func proxyProtocolTCPAddrPair(sourceAddr, destinationAddr net.Addr) (*net.TCPAddr, *net.TCPAddr, bool) {
	sourceTCPAddr, ok := sourceAddr.(*net.TCPAddr)
	if !ok || sourceTCPAddr == nil {
		return nil, nil, false
	}
	destinationTCPAddr, ok := destinationAddr.(*net.TCPAddr)
	if !ok || destinationTCPAddr == nil {
		return nil, nil, false
	}
	if sourceTCPAddr.Port < 0 || sourceTCPAddr.Port > 65535 || destinationTCPAddr.Port < 0 || destinationTCPAddr.Port > 65535 {
		return nil, nil, false
	}

	sourceIPv4 := sourceTCPAddr.IP.To4()
	destinationIPv4 := destinationTCPAddr.IP.To4()
	if sourceIPv4 != nil || destinationIPv4 != nil {
		return sourceTCPAddr, destinationTCPAddr, sourceIPv4 != nil && destinationIPv4 != nil
	}

	sourceIPv6 := sourceTCPAddr.IP.To16()
	destinationIPv6 := destinationTCPAddr.IP.To16()
	return sourceTCPAddr, destinationTCPAddr, sourceIPv6 != nil && destinationIPv6 != nil
}

func unknownProxyProtocolHeader(version byte) *proxyproto.Header {
	return &proxyproto.Header{
		Version:           version,
		Command:           proxyproto.LOCAL,
		TransportProtocol: proxyproto.UNSPEC,
	}
}
