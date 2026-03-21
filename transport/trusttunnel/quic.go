package trusttunnel

import (
	"context"
	"errors"
	"net"
	"runtime"

	"github.com/metacubex/mihomo/transport/tuic/common"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

func (c *Client) quicRoundTripper(tlsConfig *vmess.TLSConfig, congestionControlName string, cwnd int) error {
	stdConfig, err := tlsConfig.ToStdConfig()
	if err != nil {
		return err
	}
	c.roundTripper = &http3.Transport{
		TLSClientConfig: stdConfig,
		QUICConfig: &quic.Config{
			Versions:                   []quic.Version{quic.Version1},
			MaxIdleTimeout:             DefaultQuicMaxIdleTimeout,
			InitialStreamReceiveWindow: DefaultQuicStreamReceiveWindow,
			DisablePathMTUDiscovery:    !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
			Allow0RTT:                  false,
		},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			addrPort, err := c.resolv(ctx, c.server)
			if err != nil {
				return nil, err
			}
			err = tlsConfig.ECH.ClientHandle(ctx, tlsCfg)
			if err != nil {
				return nil, err
			}
			packetConn, err := c.dialer.ListenPacket(ctx, "udp", "", addrPort)
			if err != nil {
				return nil, err
			}
			quicConn, err := quic.DialEarly(ctx, packetConn, net.UDPAddrFromAddrPort(addrPort), tlsCfg, cfg)
			if err != nil {
				_ = packetConn.Close()
				return nil, err
			}
			common.SetCongestionController(quicConn, congestionControlName, cwnd)
			return quicConn, nil
		},
	}
	return nil
}

func (s *Service) configHTTP3Server(tlsConfig *tls.Config, udpConn net.PacketConn) error {
	tlsConfig = http3.ConfigureTLSConfig(tlsConfig)
	quicListener, err := quic.ListenEarly(udpConn, tlsConfig, &quic.Config{
		Versions:           []quic.Version{quic.Version1},
		MaxIdleTimeout:     DefaultQuicMaxIdleTimeout,
		MaxIncomingStreams: 1 << 60,
		Allow0RTT:          true,
	})
	if err != nil {
		return err
	}
	h3Server := &http3.Server{
		Handler:     s,
		IdleTimeout: DefaultSessionTimeout,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			common.SetCongestionController(conn, s.quicCongestionControl, s.quicCwnd)
			return ctx
		},
	}
	s.h3Server = h3Server
	s.udpConn = udpConn
	go func() {
		sErr := h3Server.ServeListener(quicListener)
		if sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
			s.logger.ErrorContext(s.ctx, "HTTP3 server close: ", sErr)
		}
	}()
	return nil
}
