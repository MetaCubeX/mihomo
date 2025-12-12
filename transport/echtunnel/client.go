package echtunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
)

type Config struct {
	Server    string
	Port      int
	WSPath    string
	Token     string
	ECHDomain string
	DNS       string
	IP        string
}

type Client struct {
	config Config
	dialer *websocket.Dialer
}

func NewClient(config Config) (*Client, error) {
	// 设置默认值
	if config.WSPath == "" {
		config.WSPath = "/tunnel"
	}
	if config.ECHDomain == "" {
		config.ECHDomain = "cloudflare-ech.com"
	}

	// TLS 配置
	tlsConfig := &tls.Config{
		ServerName: config.ECHDomain,
		MinVersion: tls.VersionTLS13,
		// TODO: 添加 ECH 配置
		// 可以使用 Mihomo 现有的 ECH 支持
	}

	dialer := &websocket.Dialer{
		TLSClientConfig:  tlsConfig,
		HandshakeTimeout: 30 * time.Second,
	}

	return &Client{
		config: config,
		dialer: dialer,
	}, nil
}

func (c *Client) DialContext(ctx context.Context, address string) (net.Conn, error) {
	// 构建 WebSocket URL
	u := url.URL{
		Scheme: "wss",
		Host:   net.JoinHostPort(c.config.Server, strconv.Itoa(c.config.Port)),
		Path:   c.config.WSPath,
	}

	// 添加 Token
	if c.config.Token != "" {
		q := u.Query()
		q.Set("token", c.config.Token)
		u.RawQuery = q.Encode()
	}

	// 建立 WebSocket 连接
	conn, _, err := c.dialer.DialContext(ctx, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}

	// 发送目标地址
	err = conn.WriteMessage(websocket.TextMessage, []byte(address))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("send target address failed: %w", err)
	}

	// 返回包装后的连接
	return &WSConn{Conn: conn}, nil
}

func (c *Client) Close() error {
	return nil
}
