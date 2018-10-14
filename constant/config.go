package constant

type General struct {
	Mode      *string `json:"mode,omitempty"`
	AllowLan  *bool   `json:"allow-lan,omitempty"`
	Port      *int    `json:"port,omitempty"`
	SocksPort *int    `json:"socks-port,omitempty"`
	RedirPort *int    `json:"redir-port,omitempty"`
	LogLevel  *string `json:"log-level,omitempty"`
}
