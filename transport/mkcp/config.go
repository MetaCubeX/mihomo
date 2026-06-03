package mkcp

import (
	"crypto/cipher"
)

// Config holds the mKCP tuning and security parameters. Field semantics and
// defaults match Xray's kcpSettings so a mihomo client interoperates with an
// Xray mKCP server.
type Config struct {
	Mtu              uint32 // maximum transmission unit, default 1350
	Tti              uint32 // transmission time interval in ms, default 50
	UplinkCapacity   uint32 // uplink bandwidth in MB/s, default 5
	DownlinkCapacity uint32 // downlink bandwidth in MB/s, default 20
	Congestion       bool   // enable congestion control, default false
	WriteBufferSize  uint32 // write buffer in bytes, default 2MB
	ReadBufferSize   uint32 // read buffer in bytes, default 2MB
	Seed             string // security seed; empty uses the default authenticator
	Header           string // header masquerade type (none/srtp/utp/wechat-video/wireguard)
}

func (c *Config) GetMTUValue() uint32 {
	if c == nil || c.Mtu == 0 {
		return 1350
	}
	return c.Mtu
}

func (c *Config) GetTTIValue() uint32 {
	if c == nil || c.Tti == 0 {
		return 50
	}
	return c.Tti
}

func (c *Config) GetUplinkCapacityValue() uint32 {
	if c == nil || c.UplinkCapacity == 0 {
		return 5
	}
	return c.UplinkCapacity
}

func (c *Config) GetDownlinkCapacityValue() uint32 {
	if c == nil || c.DownlinkCapacity == 0 {
		return 20
	}
	return c.DownlinkCapacity
}

func (c *Config) GetWriteBufferSize() uint32 {
	if c == nil || c.WriteBufferSize == 0 {
		return 2 * 1024 * 1024
	}
	return c.WriteBufferSize
}

func (c *Config) GetReadBufferSize() uint32 {
	if c == nil || c.ReadBufferSize == 0 {
		return 2 * 1024 * 1024
	}
	return c.ReadBufferSize
}

// GetSecurity returns the AEAD used to authenticate/encrypt packets. A non-empty
// Seed selects AES-128-GCM; otherwise the legacy SimpleAuthenticator is used.
func (c *Config) GetSecurity() (cipher.AEAD, error) {
	if c.Seed != "" {
		return NewAEADAESGCMBasedOnSeed(c.Seed), nil
	}
	return NewSimpleAuthenticator(), nil
}

// GetPackerHeader returns the configured header masquerade, or nil for none.
func (c *Config) GetPackerHeader() (PacketHeader, error) {
	return NewPacketHeader(c.Header)
}

func (c *Config) GetSendingInFlightSize() uint32 {
	size := c.GetUplinkCapacityValue() * 1024 * 1024 / c.GetMTUValue() / (1000 / c.GetTTIValue())
	if size < 8 {
		size = 8
	}
	return size
}

func (c *Config) GetSendingBufferSize() uint32 {
	return c.GetWriteBufferSize() / c.GetMTUValue()
}

func (c *Config) GetReceivingInFlightSize() uint32 {
	size := c.GetDownlinkCapacityValue() * 1024 * 1024 / c.GetMTUValue() / (1000 / c.GetTTIValue())
	if size < 8 {
		size = 8
	}
	return size
}

func (c *Config) GetReceivingBufferSize() uint32 {
	return c.GetReadBufferSize() / c.GetMTUValue()
}
