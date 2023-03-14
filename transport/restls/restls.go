package restls

import (
	"net"

	tls "github.com/3andne/restls-client-go"
)

const (
	Mode string = "restls"
)

// Restls
type Restls struct {
	net.Conn
	firstPacketCache []byte
	firstPacket      bool
}

func (r *Restls) Read(b []byte) (int, error) {
	if err := r.Conn.(*tls.UConn).Handshake(); err != nil {
		return 0, err
	}
	n, err := r.Conn.(*tls.UConn).Read(b)
	return n, err
}

func (r *Restls) Write(b []byte) (int, error) {
	if r.firstPacket {
		r.firstPacketCache = append([]byte(nil), b...)
		r.firstPacket = false
		return len(b), nil
	}
	if len(r.firstPacketCache) != 0 {
		b = append(r.firstPacketCache, b...)
		r.firstPacketCache = nil
	}
	n, err := r.Conn.(*tls.UConn).Write(b)
	return n, err
}

// NewRestls return a Restls Connection
func NewRestls(conn net.Conn, config *tls.Config) (net.Conn, error) {
	if config != nil {
		clientIDPtr := config.ClientID.Load()
		if clientIDPtr != nil {
			return &Restls{
				Conn:        tls.UClient(conn, config, *clientIDPtr),
				firstPacket: true,
			}, nil
		}
	}
	return &Restls{
		Conn:        tls.UClient(conn, config, tls.HelloChrome_Auto),
		firstPacket: true,
	}, nil
}
