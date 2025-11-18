package outbound

import (
	"strings"

	"github.com/metacubex/mihomo/transport/xhttp"
	tls "github.com/metacubex/utls"
)

func ensureHTTP3TLS(cfg *xhttp.Config, fallbackHost string, skipVerify bool) {
	if cfg == nil {
		return
	}
	if strings.EqualFold(cfg.HTTPVersion, "3") {
		host := cfg.Host
		if host == "" {
			host = fallbackHost
		}
		tlsCfg := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: skipVerify,
			MinVersion:         tls.VersionTLS13,
			NextProtos:         []string{"h3"},
		}
		cfg.WithInternalTLS(tlsCfg)
	}
	if cfg.Download != nil {
		ensureHTTP3TLS(cfg.Download, fallbackHost, skipVerify)
	}
}
