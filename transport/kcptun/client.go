package kcptun

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/kcp-go"
	"github.com/metacubex/randv2"
	"github.com/metacubex/smux"
)

const Mode = "kcptun"

type DialFn func(ctx context.Context) (net.PacketConn, net.Addr, error)

type Client struct {
	once   sync.Once
	config Config
	block  kcp.BlockCrypt

	ctx    context.Context
	cancel context.CancelFunc

	numconn uint16
	muxes   []timedSession
	rr      uint16
	connMu  sync.Mutex

	chScavenger chan timedSession
}

func NewClient(config Config) *Client {
	config.FillDefaults()
	block := config.NewBlock()

	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		config: config,
		block:  block,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (c *Client) Close() error {
	c.cancel()
	return nil
}

func (c *Client) createConn(ctx context.Context, dial DialFn) (*smux.Session, error) {
	conn, addr, err := dial(ctx)
	if err != nil {
		return nil, err
	}

	config := c.config
	convid := randv2.Uint32()
	kcpconn, err := kcp.NewConn4(convid, addr, c.block, config.DataShard, config.ParityShard, true, conn)
	if err != nil {
		return nil, err
	}
	kcpconn.SetStreamMode(true)
	kcpconn.SetWriteDelay(false)
	kcpconn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
	kcpconn.SetWindowSize(config.SndWnd, config.RcvWnd)
	kcpconn.SetMtu(config.MTU)
	kcpconn.SetACKNoDelay(config.AckNodelay)
	kcpconn.SetRateLimit(uint32(config.RateLimit))

	_ = kcpconn.SetDSCP(config.DSCP)
	_ = kcpconn.SetReadBuffer(config.SockBuf)
	_ = kcpconn.SetWriteBuffer(config.SockBuf)
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = config.SmuxVer
	smuxConfig.MaxReceiveBuffer = config.SmuxBuf
	smuxConfig.MaxStreamBuffer = config.StreamBuf
	smuxConfig.MaxFrameSize = config.FrameSize
	smuxConfig.KeepAliveInterval = time.Duration(config.KeepAlive) * time.Second
	if smuxConfig.KeepAliveInterval >= smuxConfig.KeepAliveTimeout {
		smuxConfig.KeepAliveTimeout = 3 * smuxConfig.KeepAliveInterval
	}

	if err := smux.VerifyConfig(smuxConfig); err != nil {
		return nil, err
	}

	var netConn net.Conn = kcpconn
	if !config.NoComp {
		netConn = NewCompStream(netConn)
	}
	// stream multiplex
	return smux.Client(netConn, smuxConfig)
}

func (c *Client) OpenStream(ctx context.Context, dial DialFn) (*smux.Stream, error) {
	c.once.Do(func() {
		// start scavenger if autoexpire is set
		c.chScavenger = make(chan timedSession, 128)
		if c.config.AutoExpire > 0 {
			go scavenger(c.ctx, c.chScavenger, &c.config)
		}

		c.numconn = uint16(c.config.Conn)
		c.muxes = make([]timedSession, c.config.Conn)
		c.rr = uint16(0)
	})

	c.connMu.Lock()
	idx := c.rr % c.numconn

	// do auto expiration && reconnection
	if c.muxes[idx].session == nil || c.muxes[idx].session.IsClosed() ||
		(c.config.AutoExpire > 0 && time.Now().After(c.muxes[idx].expiryDate)) {
		var err error
		c.muxes[idx].session, err = c.createConn(ctx, dial)
		if err != nil {
			c.connMu.Unlock()
			return nil, err
		}
		c.muxes[idx].expiryDate = time.Now().Add(time.Duration(c.config.AutoExpire) * time.Second)
		if c.config.AutoExpire > 0 { // only when autoexpire set
			c.chScavenger <- c.muxes[idx]
		}

	}
	c.rr++
	session := c.muxes[idx].session
	c.connMu.Unlock()

	return session.OpenStream()
}

// timedSession is a wrapper for smux.Session with expiry date
type timedSession struct {
	session    *smux.Session
	expiryDate time.Time
}

// scavenger goroutine is used to close expired sessions
func scavenger(ctx context.Context, ch chan timedSession, config *Config) {
	ticker := time.NewTicker(scavengePeriod * time.Second)
	defer ticker.Stop()
	var sessionList []timedSession
	for {
		select {
		case item := <-ch:
			sessionList = append(sessionList, timedSession{
				item.session,
				item.expiryDate.Add(time.Duration(config.ScavengeTTL) * time.Second)})
		case <-ticker.C:
			var newList []timedSession
			for k := range sessionList {
				s := sessionList[k]
				if s.session.IsClosed() {
					log.Debugln("scavenger: session normally closed: %s", s.session.LocalAddr())
				} else if time.Now().After(s.expiryDate) {
					s.session.Close()
					log.Debugln("scavenger: session closed due to ttl: %s", s.session.LocalAddr())
				} else {
					newList = append(newList, sessionList[k])
				}
			}
			sessionList = newList
		case <-ctx.Done():
			return
		}
	}
}
