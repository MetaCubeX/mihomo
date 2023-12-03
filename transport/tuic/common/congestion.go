package common

import (
	"github.com/metacubex/mihomo/transport/tuic/congestion"
	congestionv2 "github.com/metacubex/mihomo/transport/tuic/congestion_v2"

	"github.com/metacubex/quic-go"
	c "github.com/metacubex/quic-go/congestion"
)

const (
	DefaultStreamReceiveWindow     = 15728640 // 15 MB/s
	DefaultConnectionReceiveWindow = 67108864 // 64 MB/s
)

func SetCongestionController(quicConn quic.Connection, cc string, cwnd int) {
	if cwnd == 0 {
		cwnd = 32
	}
	switch cc {
	case "cubic":
		quicConn.SetCongestionControl(
			congestion.NewCubicSender(
				congestion.DefaultClock{},
				congestion.GetInitialPacketSize(quicConn.RemoteAddr()),
				false,
			),
		)
	case "new_reno":
		quicConn.SetCongestionControl(
			congestion.NewCubicSender(
				congestion.DefaultClock{},
				congestion.GetInitialPacketSize(quicConn.RemoteAddr()),
				true,
			),
		)
	case "bbr_meta_v1":
		quicConn.SetCongestionControl(
			congestion.NewBBRSender(
				congestion.DefaultClock{},
				congestion.GetInitialPacketSize(quicConn.RemoteAddr()),
				c.ByteCount(cwnd)*congestion.InitialMaxDatagramSize,
				congestion.DefaultBBRMaxCongestionWindow*congestion.InitialMaxDatagramSize,
			),
		)
	case "bbr_meta_v2":
		fallthrough
	case "bbr":
		quicConn.SetCongestionControl(
			congestionv2.NewBbrSender(
				congestionv2.DefaultClock{},
				congestionv2.GetInitialPacketSize(quicConn.RemoteAddr()),
				c.ByteCount(cwnd),
			),
		)
	}
}
