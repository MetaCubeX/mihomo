package inbound

import (
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/transport/kcptun"
)

type KcpTun struct {
	Enable       bool   `inbound:"enable"`
	Key          string `inbound:"key,omitempty"`
	Crypt        string `inbound:"crypt,omitempty"`
	Mode         string `inbound:"mode,omitempty"`
	Conn         int    `inbound:"conn,omitempty"`
	AutoExpire   int    `inbound:"autoexpire,omitempty"`
	ScavengeTTL  int    `inbound:"scavengettl,omitempty"`
	MTU          int    `inbound:"mtu,omitempty"`
	RateLimit    int    `inbound:"ratelimit,omitempty"`
	SndWnd       int    `inbound:"sndwnd,omitempty"`
	RcvWnd       int    `inbound:"rcvwnd,omitempty"`
	DataShard    int    `inbound:"datashard,omitempty"`
	ParityShard  int    `inbound:"parityshard,omitempty"`
	DSCP         int    `inbound:"dscp,omitempty"`
	NoComp       bool   `inbound:"nocomp,omitempty"`
	AckNodelay   bool   `inbound:"acknodelay,omitempty"`
	NoDelay      int    `inbound:"nodelay,omitempty"`
	Interval     int    `inbound:"interval,omitempty"`
	Resend       int    `inbound:"resend,omitempty"`
	NoCongestion int    `inbound:"nc,omitempty"`
	SockBuf      int    `inbound:"sockbuf,omitempty"`
	SmuxVer      int    `inbound:"smuxver,omitempty"`
	SmuxBuf      int    `inbound:"smuxbuf,omitempty"`
	FrameSize    int    `inbound:"framesize,omitempty"`
	StreamBuf    int    `inbound:"streambuf,omitempty"`
	KeepAlive    int    `inbound:"keepalive,omitempty"`
}

func (c KcpTun) Build() LC.KcpTun {
	return LC.KcpTun{
		Enable: c.Enable,
		Config: kcptun.Config{
			Key:          c.Key,
			Crypt:        c.Crypt,
			Mode:         c.Mode,
			Conn:         c.Conn,
			AutoExpire:   c.AutoExpire,
			ScavengeTTL:  c.ScavengeTTL,
			MTU:          c.MTU,
			RateLimit:    c.RateLimit,
			SndWnd:       c.SndWnd,
			RcvWnd:       c.RcvWnd,
			DataShard:    c.DataShard,
			ParityShard:  c.ParityShard,
			DSCP:         c.DSCP,
			NoComp:       c.NoComp,
			AckNodelay:   c.AckNodelay,
			NoDelay:      c.NoDelay,
			Interval:     c.Interval,
			Resend:       c.Resend,
			NoCongestion: c.NoCongestion,
			SockBuf:      c.SockBuf,
			SmuxVer:      c.SmuxVer,
			SmuxBuf:      c.SmuxBuf,
			FrameSize:    c.FrameSize,
			StreamBuf:    c.StreamBuf,
			KeepAlive:    c.KeepAlive,
		},
	}
}
