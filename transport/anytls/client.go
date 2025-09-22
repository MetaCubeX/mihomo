package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/buf"
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
	c.sessionClient = session.NewClient(ctx, c.createOutboundTLSConnection, &c.padding, config.IdleSessionCheckInterval, config.IdleSessionTimeout, config.MinIdleSession)
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

func (c *Client) createOutboundTLSConnection(ctx context.Context) (net.Conn, error) {
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
