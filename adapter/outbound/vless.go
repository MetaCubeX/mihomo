package outbound

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/Dreamacro/clash/common/convert"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/gun"
	"github.com/Dreamacro/clash/transport/vless"
	"github.com/Dreamacro/clash/transport/vmess"
)

const (
	// max packet length
	maxLength = 1024 << 3
)

type Vless struct {
	*Base
	client *vless.Client
	option *VlessOption

	// for gun mux
	gunTLSConfig *tls.Config
	gunConfig    *gun.Config
	transport    *gun.TransportWrap
}

type VlessOption struct {
	BasicOption
	Name           string            `proxy:"name"`
	Server         string            `proxy:"server"`
	Port           int               `proxy:"port"`
	UUID           string            `proxy:"uuid"`
	Flow           string            `proxy:"flow,omitempty"`
	FlowShow       bool              `proxy:"flow-show,omitempty"`
	TLS            bool              `proxy:"tls,omitempty"`
	UDP            bool              `proxy:"udp,omitempty"`
	Network        string            `proxy:"network,omitempty"`
	HTTPOpts       HTTPOptions       `proxy:"http-opts,omitempty"`
	HTTP2Opts      HTTP2Options      `proxy:"h2-opts,omitempty"`
	GrpcOpts       GrpcOptions       `proxy:"grpc-opts,omitempty"`
	WSOpts         WSOptions         `proxy:"ws-opts,omitempty"`
	WSPath         string            `proxy:"ws-path,omitempty"`
	WSHeaders      map[string]string `proxy:"ws-headers,omitempty"`
	SkipCertVerify bool              `proxy:"skip-cert-verify,omitempty"`
	ServerName     string            `proxy:"servername,omitempty"`
}

func (v *Vless) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	var err error
	switch v.option.Network {
	case "ws":

		host, port, _ := net.SplitHostPort(v.addr)
		wsOpts := &vmess.WebsocketConfig{
			Host:                host,
			Port:                port,
			Path:                v.option.WSOpts.Path,
			MaxEarlyData:        v.option.WSOpts.MaxEarlyData,
			EarlyDataHeaderName: v.option.WSOpts.EarlyDataHeaderName,
		}

		if len(v.option.WSOpts.Headers) != 0 {
			header := http.Header{}
			for key, value := range v.option.WSOpts.Headers {
				header.Add(key, value)
			}
			wsOpts.Headers = header
		}

		wsOpts.TLS = true
		wsOpts.TLSConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ServerName:         host,
			InsecureSkipVerify: v.option.SkipCertVerify,
			NextProtos:         []string{"http/1.1"},
		}
		if v.option.ServerName != "" {
			wsOpts.TLSConfig.ServerName = v.option.ServerName
		} else if host := wsOpts.Headers.Get("Host"); host != "" {
			wsOpts.TLSConfig.ServerName = host
		} else {
			wsOpts.Headers.Set("Host", convert.RandHost())
			convert.SetUserAgent(wsOpts.Headers)
		}
		c, err = vmess.StreamWebsocketConn(c, wsOpts)
	case "http":
		// readability first, so just copy default TLS logic
		c, err = v.streamTLSOrXTLSConn(c, false)
		if err != nil {
			return nil, err
		}

		host, _, _ := net.SplitHostPort(v.addr)
		httpOpts := &vmess.HTTPConfig{
			Host:    host,
			Method:  v.option.HTTPOpts.Method,
			Path:    v.option.HTTPOpts.Path,
			Headers: v.option.HTTPOpts.Headers,
		}

		c = vmess.StreamHTTPConn(c, httpOpts)
	case "h2":
		c, err = v.streamTLSOrXTLSConn(c, true)
		if err != nil {
			return nil, err
		}

		h2Opts := &vmess.H2Config{
			Hosts: v.option.HTTP2Opts.Host,
			Path:  v.option.HTTP2Opts.Path,
		}

		c, err = vmess.StreamH2Conn(c, h2Opts)
	case "grpc":
		if v.isXTLSEnabled() {
			c, err = gun.StreamGunWithXTLSConn(c, v.gunTLSConfig, v.gunConfig)
		} else {
			c, err = gun.StreamGunWithConn(c, v.gunTLSConfig, v.gunConfig)
		}
	default:
		// default tcp network
		// handle TLS And XTLS
		c, err = v.streamTLSOrXTLSConn(c, false)
	}

	if err != nil {
		return nil, err
	}

	return v.client.StreamConn(c, parseVlessAddr(metadata))
}

func (v *Vless) streamTLSOrXTLSConn(conn net.Conn, isH2 bool) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(v.addr)

	if v.isXTLSEnabled() {
		xtlsOpts := vless.XTLSConfig{
			Host:           host,
			SkipCertVerify: v.option.SkipCertVerify,
		}

		if isH2 {
			xtlsOpts.NextProtos = []string{"h2"}
		}

		if v.option.ServerName != "" {
			xtlsOpts.Host = v.option.ServerName
		}

		return vless.StreamXTLSConn(conn, &xtlsOpts)

	} else if v.option.TLS {
		tlsOpts := vmess.TLSConfig{
			Host:           host,
			SkipCertVerify: v.option.SkipCertVerify,
		}

		if isH2 {
			tlsOpts.NextProtos = []string{"h2"}
		}

		if v.option.ServerName != "" {
			tlsOpts.Host = v.option.ServerName
		}

		return vmess.StreamTLSConn(conn, &tlsOpts)
	}

	return conn, nil
}

func (v *Vless) isXTLSEnabled() bool {
	return v.client.Addons != nil
}

// DialContext implements C.ProxyAdapter
func (v *Vless) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	// gun transport
	if v.transport != nil && len(opts) == 0 {
		c, err := gun.StreamGunWithTransport(v.transport, v.gunConfig)
		if err != nil {
			return nil, err
		}
		defer safeConnClose(c, err)

		c, err = v.client.StreamConn(c, parseVlessAddr(metadata))
		if err != nil {
			return nil, err
		}

		return NewConn(c, v), nil
	}

	c, err := dialer.DialContext(ctx, "tcp", v.addr, v.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
	}
	tcpKeepAlive(c)
	defer safeConnClose(c, err)

	c, err = v.StreamConn(c, metadata)
	return NewConn(c, v), err
}

// ListenPacketContext implements C.ProxyAdapter
func (v *Vless) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	// vless use stream-oriented udp with a special address, so we needs a net.UDPAddr
	if !metadata.Resolved() {
		ip, err := resolver.ResolveIP(metadata.Host)
		if err != nil {
			return nil, errors.New("can't resolve ip")
		}
		metadata.DstIP = ip
	}

	var c net.Conn
	// gun transport
	if v.transport != nil && len(opts) == 0 {
		c, err = gun.StreamGunWithTransport(v.transport, v.gunConfig)
		if err != nil {
			return nil, err
		}
		defer safeConnClose(c, err)

		c, err = v.client.StreamConn(c, parseVlessAddr(metadata))
	} else {
		c, err = dialer.DialContext(ctx, "tcp", v.addr, v.Base.DialOptions(opts...)...)
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
		}
		tcpKeepAlive(c)
		defer safeConnClose(c, err)

		c, err = v.StreamConn(c, metadata)
	}

	if err != nil {
		return nil, fmt.Errorf("new vless client error: %v", err)
	}

	return v.ListenPacketOnStreamConn(c, metadata)
}

// ListenPacketOnStreamConn implements C.ProxyAdapter
func (v *Vless) ListenPacketOnStreamConn(c net.Conn, metadata *C.Metadata) (_ C.PacketConn, err error) {
	return newPacketConn(&vlessPacketConn{Conn: c, rAddr: metadata.UDPAddr()}, v), nil
}

// SupportUOT implements C.ProxyAdapter
func (v *Vless) SupportUOT() bool {
	return true
}

func parseVlessAddr(metadata *C.Metadata) *vless.DstAddr {
	var addrType byte
	var addr []byte
	switch metadata.AddrType {
	case C.AtypIPv4:
		addrType = vless.AtypIPv4
		addr = make([]byte, net.IPv4len)
		copy(addr[:], metadata.DstIP.AsSlice())
	case C.AtypIPv6:
		addrType = vless.AtypIPv6
		addr = make([]byte, net.IPv6len)
		copy(addr[:], metadata.DstIP.AsSlice())
	case C.AtypDomainName:
		addrType = vless.AtypDomainName
		addr = make([]byte, len(metadata.Host)+1)
		addr[0] = byte(len(metadata.Host))
		copy(addr[1:], metadata.Host)
	}

	port, _ := strconv.ParseUint(metadata.DstPort, 10, 16)
	return &vless.DstAddr{
		UDP:      metadata.NetWork == C.UDP,
		AddrType: addrType,
		Addr:     addr,
		Port:     uint(port),
	}
}

type vlessPacketConn struct {
	net.Conn
	rAddr  net.Addr
	remain int
	mux    sync.Mutex
	cache  [2]byte
}

func (c *vlessPacketConn) writePacket(payload []byte) (int, error) {
	binary.BigEndian.PutUint16(c.cache[:], uint16(len(payload)))

	if _, err := c.Conn.Write(c.cache[:]); err != nil {
		return 0, err
	}

	return c.Conn.Write(payload)
}

func (c *vlessPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	total := len(b)
	if total == 0 {
		return 0, nil
	}

	if total <= maxLength {
		return c.writePacket(b)
	}

	offset := 0

	for offset < total {
		cursor := offset + maxLength
		if cursor > total {
			cursor = total
		}

		n, err := c.writePacket(b[offset:cursor])
		if err != nil {
			return offset + n, err
		}

		offset = cursor
		if offset == total {
			break
		}
	}

	return total, nil
}

func (c *vlessPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	if c.remain > 0 {
		length := len(b)
		if c.remain < length {
			length = c.remain
		}

		n, err := c.Conn.Read(b[:length])
		if err != nil {
			return 0, c.rAddr, err
		}

		c.remain -= n
		return n, c.rAddr, nil
	}

	if _, err := c.Conn.Read(b[:2]); err != nil {
		return 0, c.rAddr, err
	}

	total := int(binary.BigEndian.Uint16(b[:2]))
	if total == 0 {
		return 0, c.rAddr, nil
	}

	length := len(b)
	if length > total {
		length = total
	}

	if _, err := io.ReadFull(c.Conn, b[:length]); err != nil {
		return 0, c.rAddr, errors.New("read packet error")
	}

	c.remain = total - length

	return length, c.rAddr, nil
}

func NewVless(option VlessOption) (*Vless, error) {
	var addons *vless.Addons
	if option.Network != "ws" && len(option.Flow) >= 16 {
		option.Flow = option.Flow[:16]
		switch option.Flow {
		case vless.XRO, vless.XRD, vless.XRS:
			addons = &vless.Addons{
				Flow: option.Flow,
			}
		default:
			return nil, fmt.Errorf("unsupported xtls flow type: %s", option.Flow)
		}
	}

	client, err := vless.NewClient(option.UUID, addons, option.FlowShow)
	if err != nil {
		return nil, err
	}

	v := &Vless{
		Base: &Base{
			name:  option.Name,
			addr:  net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:    C.Vless,
			udp:   option.UDP,
			iface: option.Interface,
		},
		client: client,
		option: &option,
	}

	switch option.Network {
	case "h2":
		if len(option.HTTP2Opts.Host) == 0 {
			option.HTTP2Opts.Host = append(option.HTTP2Opts.Host, "www.example.com")
		}
	case "grpc":
		dialFn := func(network, addr string) (net.Conn, error) {
			c, err := dialer.DialContext(context.Background(), "tcp", v.addr, v.Base.DialOptions()...)
			if err != nil {
				return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
			}
			tcpKeepAlive(c)
			return c, nil
		}

		gunConfig := &gun.Config{
			ServiceName: v.option.GrpcOpts.GrpcServiceName,
			Host:        v.option.ServerName,
		}
		tlsConfig := &tls.Config{
			InsecureSkipVerify: v.option.SkipCertVerify,
			ServerName:         v.option.ServerName,
		}

		if v.option.ServerName == "" {
			host, _, _ := net.SplitHostPort(v.addr)
			tlsConfig.ServerName = host
			gunConfig.Host = host
		}

		v.gunTLSConfig = tlsConfig
		v.gunConfig = gunConfig
		if v.isXTLSEnabled() {
			v.transport = gun.NewHTTP2XTLSClient(dialFn, tlsConfig)
		} else {
			v.transport = gun.NewHTTP2Client(dialFn, tlsConfig)
		}
	}

	return v, nil
}
