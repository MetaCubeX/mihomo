package http2ping

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"golang.org/x/net/http2"
)

type pingerStatusCode = uint32

const (
	PINGER_STATUS_DEAD pingerStatusCode = iota
	PINGER_STATUS_PINGING
	PINGER_STATUS_IDLE
)

const (
	rttAlpha      = 0.2
	oneMinusAlpha = 1 - rttAlpha
	rttBeta       = 0.25
	oneMinusBeta  = 1 - rttBeta
)

func updateSRtt(sRtt, rtt uint32) uint32 {
	return uint32(float32(sRtt)*oneMinusAlpha + float32(rtt)*rttAlpha)
}

func updateMeanDeviation(meanDeviation, sRtt, rtt uint32) uint32 {
	return uint32(float32(meanDeviation)*oneMinusBeta + float32(Abs(int32(sRtt)-int32(rtt)))*rttBeta)
}

type http2Pinger struct {
	statusCode    atomic.Uint32
	latestRtt     atomic.Uint32
	sRtt          atomic.Uint32
	meanDeviation atomic.Uint32

	config *Config
	proxy  constant.Proxy

	hasRecordedRtt atomic.Bool
	newSRttCh      chan uint32

	ctx       context.Context
	ctxCancel context.CancelFunc
	closed    atomic.Bool
}

func NewHTTP2Pinger(config *Config, proxy constant.Proxy) *http2Pinger {
	ctx, cancel := context.WithCancel(context.Background())
	p := &http2Pinger{
		config:    config,
		proxy:     proxy,
		newSRttCh: make(chan uint32),
		ctx:       ctx,
		ctxCancel: cancel,
	}
	p.statusCode.Store(PINGER_STATUS_DEAD)
	go p.pingLoop()
	return p
}

func (p *http2Pinger) doPing(tlsConn *tls.Conn, http2Conn *http2.ClientConn) (uint32, error) {
	tlsConn.SetDeadline(time.Now().Add(p.config.Interval))
	defer tlsConn.SetDeadline(time.Time{})

	start := time.Now()
	err := http2Conn.Ping(p.ctx)
	if err != nil {
		return 0, fmt.Errorf("http2 ping: %w", err)
	}
	return uint32(time.Since(start).Milliseconds()), nil
}

func (p *http2Pinger) Ping(tlsConn *tls.Conn, http2Conn *http2.ClientConn) error {
	p.statusCode.Store(PINGER_STATUS_PINGING)
	rtt, err := p.doPing(tlsConn, http2Conn)
	if err != nil {
		p.statusCode.Store(PINGER_STATUS_DEAD)
		return err
	}
	sRtt := rtt
	meanDeviation := rtt / 2
	if p.hasRecordedRtt.Load() {
		sRtt = updateSRtt(p.sRtt.Load(), rtt)
		meanDeviation = updateMeanDeviation(p.meanDeviation.Load(), sRtt, rtt)
	} else {
		p.hasRecordedRtt.Store(true)
	}
	log.Debugln("[http2ping] [%s], rtt: %d, sRtt: %d, meanDeviation: %d", p.proxy.Name(), rtt, sRtt, meanDeviation)
	p.sRtt.Store(sRtt)
	p.latestRtt.Store(rtt)
	p.meanDeviation.Store(meanDeviation)
	p.statusCode.Store(PINGER_STATUS_IDLE)
	select {
	case p.newSRttCh <- sRtt:
	default:
	}
	return nil
}

func (p *http2Pinger) Dial(ctx context.Context) (*tls.Conn, *http2.ClientConn, error) {
	log.Debugln("[http2ping] [%s] dialing conn to %v", p.proxy.Name(), p.config.HTTP2Server)
	rawConn, err := dialProxyConn(ctx, p.proxy, p.config.HTTP2Server.String())
	if err != nil {
		return nil, nil, fmt.Errorf("dial proxy conn: %w", err)
	}
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: p.config.HTTP2Server.Hostname(),
		NextProtos: []string{"h2"},
	})
	// set deadline for protocol handshake
	tlsConn.SetDeadline(time.Now().Add(p.config.Interval * 5))
	defer tlsConn.SetDeadline(time.Time{})
	tr := http2.Transport{}
	http2Conn, err := tr.NewClientConn(tlsConn)
	if err != nil {
		return nil, nil, fmt.Errorf("new client conn: %w", err)
	}
	return tlsConn, http2Conn, nil
}

func (p *http2Pinger) pingLoop() {
	loopFn := func() (err error) {
		tlsConn, http2Conn, err := p.Dial(context.Background())
		if err != nil {
			p.statusCode.Store(PINGER_STATUS_DEAD)
			return err
		}
		defer http2Conn.Close()
		for {
			if p.closed.Load() {
				return nil
			}
			err = p.Ping(tlsConn, http2Conn)
			if err != nil {
				return err
			}
			time.Sleep(p.config.Interval)
		}
	}
	for {
		if p.closed.Load() {
			return
		}
		err := loopFn()
		log.Debugln("[http2ping] [%s] pingLoop err: %v, wait for retry...", p.proxy.Name(), err)
		time.Sleep(p.config.Interval * 5)
	}
}

func (p *http2Pinger) GetSmoothRtt() uint32 {
	switch p.statusCode.Load() {
	case PINGER_STATUS_DEAD:
		return math.MaxUint32
	case PINGER_STATUS_PINGING:
		fallthrough
	case PINGER_STATUS_IDLE:
		return p.sRtt.Load()
	}
	panic("unreachable")
}

func (p *http2Pinger) GetProxy() constant.Proxy {
	return p.proxy
}

func (p *http2Pinger) Close() error {
	p.closed.Store(true)
	p.ctxCancel()
	return nil
}

func (p *http2Pinger) String() string {
	return p.proxy.Name()
}

func (p *http2Pinger) GetStatus() *PingerStatus {
	return &PingerStatus{
		Name:          p.GetProxy().Name(),
		StatusCode:    p.statusCode.Load(),
		LatestRtt:     p.latestRtt.Load(),
		SRtt:          p.GetSmoothRtt(),
		MeanDeviation: p.meanDeviation.Load(),
	}
}
