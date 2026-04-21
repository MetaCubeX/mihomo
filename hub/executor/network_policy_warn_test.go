package executor

import (
	"testing"

	"github.com/metacubex/mihomo/config"
)

func TestIsNonLoopbackBind(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"", false},                    // empty → not exposed
		{"127.0.0.1:9090", false},      // IPv4 loopback
		{"[::1]:9090", false},          // IPv6 loopback
		{"localhost:9090", false},      // hostname
		{"LocalHost:9090", false},      // case-insensitive hostname
		{"ip6-localhost:9090", false},  // IPv6 alias
		{"ip6-loopback:9090", false},   // alternate IPv6 alias
		{":9090", true},                // bind-all
		{"0.0.0.0:9090", true},         // IPv4 wildcard
		{"[::]:9090", true},             // IPv6 wildcard
		{"192.168.1.1:9090", true},      // LAN IP
		{"myhost:9090", true},            // unknown hostname → assume exposed
		{"bogus", false},                 // unparseable → conservative no
	}
	for _, c := range cases {
		if got := isNonLoopbackBind(c.addr); got != c.want {
			t.Errorf("isNonLoopbackBind(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

func TestHasStrongClientAuth(t *testing.T) {
	cases := []struct {
		name string
		tls  *config.TLS
		want bool
	}{
		{"nil tls", nil, false},
		{"empty cert", &config.TLS{ClientAuthType: "require-and-verify"}, false},
		{"cert + empty type", &config.TLS{ClientAuthCert: "/etc/ca.pem"}, false},
		{"cert + request", &config.TLS{ClientAuthCert: "/etc/ca.pem", ClientAuthType: "request"}, false},
		{"cert + verify-if-given", &config.TLS{ClientAuthCert: "/etc/ca.pem", ClientAuthType: "verify-if-given"}, false},
		{"cert + require-any", &config.TLS{ClientAuthCert: "/etc/ca.pem", ClientAuthType: "require-any"}, false},
		{"cert + require-and-verify", &config.TLS{ClientAuthCert: "/etc/ca.pem", ClientAuthType: "require-and-verify"}, true},
		{"cert + Require-And-Verify (case)", &config.TLS{ClientAuthCert: "/etc/ca.pem", ClientAuthType: "Require-And-Verify"}, true},
	}
	for _, c := range cases {
		if got := hasStrongClientAuth(c.tls); got != c.want {
			t.Errorf("%s: hasStrongClientAuth = %v, want %v", c.name, got, c.want)
		}
	}
}
