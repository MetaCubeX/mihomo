package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/session"
	"github.com/metacubex/mihomo/transport/vmess"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type ClientConfig struct {
	Password                 string
	IdleSessionCheckInterval time.Duration
	IdleSessionTimeout       time.Duration
	MinIdleSession           int
	Server                   M.Socksaddr
	Dialer                   N.Dialer
	TLSConfig                *vmess.TLSConfig
}

type Client struct {
	passwordSha256 []byte
	tlsConfig      *vmess.TLSConfig
	dialer         N.Dialer
	server         M.Socksaddr
	sessionClient  *session.Client
	padding        atomic.Pointer[padding.PaddingFactory]
}

func NewClient(ctx context.Context, config ClientConfig) *Client {
	pw := sha256.Sum256([]byte(config.Password))
	c := &Client{
		passwordSha256: pw[:],
		tlsConfig:      config.TLSConfig,
		dialer:         config.Dialer,
		server:         config.Server,
	}
	// Initialize the padding state of this client
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &c.padding)
	c.sessionClient = session.NewClient(ctx, c.CreateOutboundTLSConnection, &c.padding, config.IdleSessionCheckInterval, config.IdleSessionTimeout, config.MinIdleSession)
	return c
}

func (c *Client) CreateProxy(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.sessionClient.CreateStream(ctx)
	if err != nil {
		return nil, err
	}
	err = M.SocksaddrSerializer.WriteAddrPort(conn, destination)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) CreateOutboundTLSConnection(ctx context.Context) (net.Conn, error) {
	conn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.server)
	if err != nil {
		return nil, err
	}

	b := buf.NewPacket()
	defer b.Release()

	b.Write(c.passwordSha256)
	var paddingLen int
	if pad := c.padding.Load().GenerateRecordPayloadSizes(0); len(pad) > 0 {
		paddingLen = pad[0]
	}
	binary.BigEndian.PutUint16(b.Extend(2), uint16(paddingLen))
	if paddingLen > 0 {
		b.WriteZeroN(paddingLen)
	}

	// REALITY as the outermost TLS if configured
	rcfg := c.tlsConfig.Reality
	if rcfg != nil && rcfg.PublicKey != nil {
		// ALPN: default to common set if not provided / filter out h3
		next := append([]string(nil), c.tlsConfig.NextProtos...)
		if len(next) == 0 {
			next = []string{"h2", "http/1.1"}
		} else {
			keep := make([]string, 0, len(next))
			for _, p := range next {
				if p == "h2" || p == "http/1.1" {
					keep = append(keep, p)
				}
			}
			if len(keep) == 0 {
				keep = []string{"h2", "http/1.1"}
			}
			next = keep
		}

		// SNI
		sni := c.tlsConfig.Host
		if sni == "" {
			log.Errorln("Reality: empty SNI/Host in tls config")
			_ = conn.Close()
			return nil, errors.New("reality: empty sni/host")
		}

		// uTLS fingerprint (prefer node value; otherwise use 'chrome' for stability)
		var fp tlsC.UClientHelloID
		if id, ok := tlsC.GetFingerprint(c.tlsConfig.ClientFingerprint); ok {
			fp = id
		} else if id, ok := tlsC.GetFingerprint("chrome"); ok {
			fp = id
		}

		std := &tlsC.Config{
			ServerName:         sni,
			InsecureSkipVerify: c.tlsConfig.SkipCertVerify,
			NextProtos:         next,
		}

		rc, rerr := tlsC.GetRealityConn(ctx, conn, fp, std, rcfg)
		if rerr != nil {
			log.Errorln("Reality handshake failed: %s", rerr.Error())
			_ = conn.Close()
			return nil, rerr
		}

		if _, werr := b.WriteTo(rc); werr != nil {
			log.Errorln("AnyTLS preface write failed: %s", werr.Error())
			_ = rc.Close()
			return nil, werr
		}
		return rc, nil
	}

	tlsConn, err := vmess.StreamTLSConn(ctx, conn, c.tlsConfig)
	if err != nil {
		conn.Close()
		return nil, err
	}

	_, err = b.WriteTo(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (h *Client) Close() error {
	return h.sessionClient.Close()
}
