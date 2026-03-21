package config

type ShadowTLS struct {
	Enable                 bool
	Version                int
	Password               string
	Users                  []ShadowTLSUser
	Handshake              ShadowTLSHandshakeOptions
	HandshakeForServerName map[string]ShadowTLSHandshakeOptions
	StrictMode             bool
	WildcardSNI            string
}

type ShadowTLSUser struct {
	Name     string
	Password string
}

type ShadowTLSHandshakeOptions struct {
	Dest  string
	Proxy string
}
