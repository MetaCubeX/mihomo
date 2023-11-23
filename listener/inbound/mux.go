package inbound

import "github.com/metacubex/mihomo/listener/sing"

type MuxOption struct {
	Padding bool          `inbound:"padding,omitempty"`
	Brutal  BrutalOptions `inbound:"brutal,omitempty"`
}

type BrutalOptions struct {
	Enabled bool   `inbound:"enabled,omitempty"`
	Up      string `inbound:"up,omitempty"`
	Down    string `inbound:"down,omitempty"`
}

func (m MuxOption) Build() sing.MuxOption {
	return sing.MuxOption{
		Padding: m.Padding,
		Brutal: sing.BrutalOptions{
			Enabled: m.Brutal.Enabled,
			Up:      m.Brutal.Up,
			Down:    m.Brutal.Down,
		},
	}
}
