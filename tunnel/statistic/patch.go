package statistic

import (
	"net"
)

func (m *Manager) Total() (up, down int64) {
	return m.uploadTotal.Load(), m.downloadTotal.Load()
}

func (tt *tcpTracker) RawConn() (net.Conn, bool) {
	if tt.Chain.Last() == "DIRECT" {
		return tt.Conn, true
	}

	return nil, false
}

func (ut *udpTracker) RawPacketConn() (net.PacketConn, bool) {
	if ut.Chain.Last() == "DIRECT" {
		return ut.PacketConn, true
	}

	return nil, false
}
