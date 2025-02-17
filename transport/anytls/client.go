package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"net"
	"time"

	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/session"
	"github.com/metacubex/mihomo/transport/vmess"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type ClientConfig struct {
	Password                 string
	IdleSessionCheckInterval time.Duration
	IdleSessionTimeout       time.Duration
	Server                   M.Socksaddr
	Dialer                   N.Dialer
	TLSConfig                *tls.Config
	ClientFingerprint        string
}

type Client struct {
	passwordSha256    []byte
	tlsConfig         *tls.Config
	clientFingerprint string
	dialer            N.Dialer
	server            M.Socksaddr
	sessionClient     *session.Client
	padding           atomic.TypedValue[*padding.PaddingFactory]
}

func NewClient(ctx context.Context, config ClientConfig) *Client {
	pw := sha256.Sum256([]byte(config.Password))
	c := &Client{
		passwordSha256:    pw[:],
		tlsConfig:         config.TLSConfig,
		clientFingerprint: config.ClientFingerprint,
		dialer:            config.Dialer,
		server:            config.Server,
	}
	// Initialize the padding state of this client
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &c.padding)
	c.sessionClient = session.NewClient(ctx, c.CreateOutboundTLSConnection, &c.padding, config.IdleSessionCheckInterval, config.IdleSessionTimeout)
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
	b.Write(c.passwordSha256)
	var paddingLen int
	if pad := c.padding.Load().GenerateRecordPayloadSizes(0); len(pad) > 0 {
		paddingLen = pad[0]
	}
	binary.BigEndian.PutUint16(b.Extend(2), uint16(paddingLen))
	if paddingLen > 0 {
		b.WriteZeroN(paddingLen)
	}

	getTlsConn := func() (net.Conn, error) {
		if len(c.clientFingerprint) != 0 {
			utlsConn, valid := vmess.GetUTLSConn(conn, c.clientFingerprint, c.tlsConfig)
			if valid {
				ctx, cancel := context.WithTimeout(ctx, C.DefaultTLSTimeout)
				defer cancel()

				err := utlsConn.(*tlsC.UConn).HandshakeContext(ctx)
				return utlsConn, err
			}
		}

		tlsConn := tls.Client(conn, c.tlsConfig)

		ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
		defer cancel()

		err = tlsConn.HandshakeContext(ctx)
		return tlsConn, err
	}
	tlsConn, err := getTlsConn()
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
