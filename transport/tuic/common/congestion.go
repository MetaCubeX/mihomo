package common

import (
	"github.com/Dreamacro/clash/transport/tuic/congestion"

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
				nil,
			),
		)
	case "new_reno":
		quicConn.SetCongestionControl(
			congestion.NewCubicSender(
				congestion.DefaultClock{},
				congestion.GetInitialPacketSize(quicConn.RemoteAddr()),
				true,
				nil,
			),
		)
	case "bbr":
		quicConn.SetCongestionControl(
			congestion.NewBBRSender(
				congestion.DefaultClock{},
				congestion.GetInitialPacketSize(quicConn.RemoteAddr()),
				c.ByteCount(cwnd)*congestion.InitialMaxDatagramSize,
				congestion.DefaultBBRMaxCongestionWindow*congestion.InitialMaxDatagramSize,
			),
		)
	}
}
