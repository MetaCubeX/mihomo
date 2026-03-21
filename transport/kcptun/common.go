package kcptun

import (
	"crypto/sha1"

	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/kcp-go"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// SALT is use for pbkdf2 key expansion
	SALT = "kcp-go"
	// maximum supported smux version
	maxSmuxVer = 2
	// scavenger check period
	scavengePeriod = 5
)

type Config struct {
	Key          string `json:"key"`
	Crypt        string `json:"crypt"`
	Mode         string `json:"mode"`
	Conn         int    `json:"conn"`
	AutoExpire   int    `json:"autoexpire"`
	ScavengeTTL  int    `json:"scavengettl"`
	MTU          int    `json:"mtu"`
	RateLimit    int    `json:"ratelimit"`
	SndWnd       int    `json:"sndwnd"`
	RcvWnd       int    `json:"rcvwnd"`
	DataShard    int    `json:"datashard"`
	ParityShard  int    `json:"parityshard"`
	DSCP         int    `json:"dscp"`
	NoComp       bool   `json:"nocomp"`
	AckNodelay   bool   `json:"acknodelay"`
	NoDelay      int    `json:"nodelay"`
	Interval     int    `json:"interval"`
	Resend       int    `json:"resend"`
	NoCongestion int    `json:"nc"`
	SockBuf      int    `json:"sockbuf"`
	SmuxVer      int    `json:"smuxver"`
	SmuxBuf      int    `json:"smuxbuf"`
	FrameSize    int    `json:"framesize"`
	StreamBuf    int    `json:"streambuf"`
	KeepAlive    int    `json:"keepalive"`
}

func (config *Config) FillDefaults() {
	if config.Key == "" {
		config.Key = "it's a secrect"
	}
	if config.Crypt == "" {
		config.Crypt = "aes"
	}
	if config.Mode == "" {
		config.Mode = "fast"
	}
	if config.Conn == 0 {
		config.Conn = 1
	}
	if config.ScavengeTTL == 0 {
		config.ScavengeTTL = 600
	}
	if config.MTU == 0 {
		config.MTU = 1350
	}
	if config.SndWnd == 0 {
		config.SndWnd = 128
	}
	if config.RcvWnd == 0 {
		config.RcvWnd = 512
	}
	if config.DataShard == 0 {
		config.DataShard = 10
	}
	if config.ParityShard == 0 {
		config.ParityShard = 3
	}
	if config.Interval == 0 {
		config.Interval = 50
	}
	if config.SockBuf == 0 {
		config.SockBuf = 4194304
	}
	if config.SmuxVer == 0 {
		config.SmuxVer = 1
	}
	if config.SmuxBuf == 0 {
		config.SmuxBuf = 4194304
	}
	if config.FrameSize == 0 {
		config.FrameSize = 8192
	}
	if config.StreamBuf == 0 {
		config.StreamBuf = 2097152
	}
	if config.KeepAlive == 0 {
		config.KeepAlive = 10
	}
	switch config.Mode {
	case "normal":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 40, 2, 1
	case "fast":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 30, 2, 1
	case "fast2":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 20, 2, 1
	case "fast3":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 10, 2, 1
	}

	// SMUX Version check
	if config.SmuxVer > maxSmuxVer {
		log.Warnln("unsupported smux version: %d", config.SmuxVer)
		config.SmuxVer = maxSmuxVer
	}

	// Scavenge parameters check
	if config.AutoExpire != 0 && config.ScavengeTTL > config.AutoExpire {
		log.Warnln("WARNING: scavengettl is bigger than autoexpire, connections may race hard to use bandwidth.")
		log.Warnln("Try limiting scavengettl to a smaller value.")
	}
}

func (config *Config) NewBlock() (block kcp.BlockCrypt) {
	pass := pbkdf2.Key([]byte(config.Key), []byte(SALT), 4096, 32, sha1.New)
	switch config.Crypt {
	case "null":
		block = nil
	case "tea":
		block, _ = kcp.NewTEABlockCrypt(pass[:16])
	case "xor":
		block, _ = kcp.NewSimpleXORBlockCrypt(pass)
	case "none":
		block, _ = kcp.NewNoneBlockCrypt(pass)
	case "aes-128":
		block, _ = kcp.NewAESBlockCrypt(pass[:16])
	case "aes-192":
		block, _ = kcp.NewAESBlockCrypt(pass[:24])
	case "blowfish":
		block, _ = kcp.NewBlowfishBlockCrypt(pass)
	case "twofish":
		block, _ = kcp.NewTwofishBlockCrypt(pass)
	case "cast5":
		block, _ = kcp.NewCast5BlockCrypt(pass[:16])
	case "3des":
		block, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
	case "xtea":
		block, _ = kcp.NewXTEABlockCrypt(pass[:16])
	case "salsa20":
		block, _ = kcp.NewSalsa20BlockCrypt(pass)
	case "aes-128-gcm":
		block, _ = kcp.NewAESGCMCrypt(pass[:16])
	default:
		config.Crypt = "aes"
		block, _ = kcp.NewAESBlockCrypt(pass)
	}
	return
}
