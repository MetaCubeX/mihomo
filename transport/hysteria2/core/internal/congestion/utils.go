package congestion

import (
	"github.com/metacubex/mihomo/transport/hysteria2/core/internal/congestion/bbr"
	"github.com/metacubex/mihomo/transport/hysteria2/core/internal/congestion/brutal"
	"github.com/metacubex/quic-go"
)

func UseBBR(conn quic.Connection) {
	conn.SetCongestionControl(bbr.NewBbrSender(
		bbr.DefaultClock{},
		bbr.GetInitialPacketSize(conn.RemoteAddr()),
	))
}

func UseBrutal(conn quic.Connection, tx uint64) {
	conn.SetCongestionControl(brutal.NewBrutalSender(tx))
}
