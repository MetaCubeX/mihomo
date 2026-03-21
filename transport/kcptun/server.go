package kcptun

import (
	"net"
	"time"

	"github.com/metacubex/kcp-go"
	"github.com/metacubex/smux"
)

type Server struct {
	config Config
	block  kcp.BlockCrypt
}

func NewServer(config Config) *Server {
	config.FillDefaults()
	block := config.NewBlock()

	return &Server{
		config: config,
		block:  block,
	}
}

func (s *Server) Serve(pc net.PacketConn, handler func(net.Conn)) error {
	lis, err := kcp.ServeConn(s.block, s.config.DataShard, s.config.ParityShard, pc)
	if err != nil {
		return err
	}
	defer lis.Close()
	_ = lis.SetDSCP(s.config.DSCP)
	_ = lis.SetReadBuffer(s.config.SockBuf)
	_ = lis.SetWriteBuffer(s.config.SockBuf)
	for {
		conn, err := lis.AcceptKCP()
		if err != nil {
			return err
		}
		conn.SetStreamMode(true)
		conn.SetWriteDelay(false)
		conn.SetNoDelay(s.config.NoDelay, s.config.Interval, s.config.Resend, s.config.NoCongestion)
		conn.SetMtu(s.config.MTU)
		conn.SetWindowSize(s.config.SndWnd, s.config.RcvWnd)
		conn.SetACKNoDelay(s.config.AckNodelay)
		conn.SetRateLimit(uint32(s.config.RateLimit))

		var netConn net.Conn = conn
		if !s.config.NoComp {
			netConn = NewCompStream(netConn)
		}

		go func() {
			// stream multiplex
			smuxConfig := smux.DefaultConfig()
			smuxConfig.Version = s.config.SmuxVer
			smuxConfig.MaxReceiveBuffer = s.config.SmuxBuf
			smuxConfig.MaxStreamBuffer = s.config.StreamBuf
			smuxConfig.MaxFrameSize = s.config.FrameSize
			smuxConfig.KeepAliveInterval = time.Duration(s.config.KeepAlive) * time.Second
			if smuxConfig.KeepAliveInterval >= smuxConfig.KeepAliveTimeout {
				smuxConfig.KeepAliveTimeout = 3 * smuxConfig.KeepAliveInterval
			}

			mux, err := smux.Server(netConn, smuxConfig)
			if err != nil {
				return
			}
			defer mux.Close()

			for {
				stream, err := mux.AcceptStream()
				if err != nil {
					return
				}
				go handler(stream)
			}
		}()

	}
}
