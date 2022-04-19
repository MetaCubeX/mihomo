package statistic

import (
	"errors"

	"github.com/Dreamacro/clash/common/snifer/tls"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"

	"go.uber.org/atomic"
)

type sniffing struct {
	C.Conn

	metadata   *C.Metadata
	totalWrite *atomic.Uint64
	allowBreak bool
}

func (r *sniffing) Read(b []byte) (int, error) {
	return r.Conn.Read(b)
}

func (r *sniffing) Write(b []byte) (int, error) {
	if r.totalWrite.Load() < 128 && r.metadata.Host == "" && (r.metadata.DstPort == "443" || r.metadata.DstPort == "8443" || r.metadata.DstPort == "993" || r.metadata.DstPort == "465" || r.metadata.DstPort == "995") {
		header, err := tls.SniffTLS(b)
		if err != nil {
			// log.Errorln("Expect no error but actually %s %s:%s:%s", err.Error(), tt.Metadata.Host, tt.Metadata.DstIP.String(), tt.Metadata.DstPort)
		} else {
			resolver.InsertHostByIP(r.metadata.DstIP, header.Domain())
			log.Warnln("use sni update host: %s ip: %s", header.Domain(), r.metadata.DstIP.String())
			if r.allowBreak {
				_ = r.Conn.Close()
				return 0, errors.New("sni update, break current link to avoid leaks")
			} else {
				r.metadata.Host = header.Domain()
			}
		}
	}

	n, err := r.Conn.Write(b)
	r.totalWrite.Add(uint64(n))

	return n, err
}

func (r *sniffing) Close() error {
	return r.Conn.Close()
}

func NewSniffing(conn C.Conn, metadata *C.Metadata, rule C.Rule) C.Conn {
	return &sniffing{
		Conn:       conn,
		metadata:   metadata,
		totalWrite: atomic.NewUint64(0),
		allowBreak: rule != nil,
	}
}
