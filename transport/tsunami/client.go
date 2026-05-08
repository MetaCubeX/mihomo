package tsunami

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net"

	"github.com/metacubex/mihomo/transport/vmess"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

// ClientConfig holds the configuration for the TSUNAMI transport client.
type ClientConfig struct {
	Password  string
	Server    M.Socksaddr
	Dialer    N.Dialer
	TLSConfig *vmess.TLSConfig
}

// Client manages TSUNAMI connections to the remote server.
type Client struct {
	passwordHash [32]byte
	tlsConfig    *vmess.TLSConfig
	dialer       N.Dialer
	server       M.Socksaddr
}

// NewClient creates a new TSUNAMI transport client.
func NewClient(ctx context.Context, config ClientConfig) *Client {
	hash := sha256.Sum256([]byte(config.Password))
	c := &Client{
		passwordHash: hash,
		tlsConfig:    config.TLSConfig,
		dialer:       config.Dialer,
		server:       config.Server,
	}
	return c
}

// CreateProxy creates a proxied connection through TSUNAMI to the given destination.
func (c *Client) CreateProxy(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.createOutboundConnection(ctx)
	if err != nil {
		return nil, err
	}

	// Write destination address for the proxy
	err = M.SocksaddrSerializer.WriteAddrPort(conn, destination)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// createOutboundConnection establishes a new TLS connection and authenticates.
func (c *Client) createOutboundConnection(ctx context.Context) (net.Conn, error) {
	// Dial raw TCP
	conn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.server)
	if err != nil {
		return nil, err
	}

	// Wrap with TLS
	tlsConn, err := vmess.StreamTLSConn(ctx, conn, c.tlsConfig)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Send authentication: SHA-256(password) + padding_length(0) + no padding
	authBuf := make([]byte, 32+2)
	copy(authBuf[:32], c.passwordHash[:])
	binary.BigEndian.PutUint16(authBuf[32:34], 0) // no padding
	_, err = tlsConn.Write(authBuf)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

// Close closes the client.
func (c *Client) Close() error {
	return nil
}
