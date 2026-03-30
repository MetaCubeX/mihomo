package xhttp

import (
	"context"
	"crypto/rand"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"
)

type XmuxConn interface {
	IsClosed() bool
}

type XmuxClient struct {
	XmuxConn     XmuxConn
	OpenUsage    atomic.Int32
	leftUsage    int32
	LeftRequests atomic.Int32
	UnreusableAt time.Time
}

type XmuxManager struct {
	mx          sync.Mutex
	xmuxConfig  *XmuxConfig
	concurrency int32
	connections int32
	newConnFunc func(ctx context.Context) (XmuxConn, error)
	xmuxClients []*XmuxClient
}

func NewXmuxManager(xmuxConfig *XmuxConfig, newConnFunc func(ctx context.Context) (XmuxConn, error)) *XmuxManager {
	if xmuxConfig == nil {
		xmuxConfig = &XmuxConfig{}
	}
	return &XmuxManager{
		xmuxConfig:  xmuxConfig,
		concurrency: xmuxConfig.GetNormalizedMaxConcurrency().Rand(),
		connections: xmuxConfig.GetNormalizedMaxConnections().Rand(),
		newConnFunc: newConnFunc,
		xmuxClients: make([]*XmuxClient, 0),
	}
}

func (m *XmuxManager) newXmuxClient(ctx context.Context) (*XmuxClient, error) {
	conn, err := m.newConnFunc(ctx)
	if err != nil {
		return nil, err
	}
	xmuxClient := &XmuxClient{
		XmuxConn:  conn,
		leftUsage: -1,
	}
	if x := m.xmuxConfig.GetNormalizedCMaxReuseTimes().Rand(); x > 0 {
		xmuxClient.leftUsage = x - 1
	}
	xmuxClient.LeftRequests.Store(math.MaxInt32)
	if x := m.xmuxConfig.GetNormalizedHMaxRequestTimes().Rand(); x > 0 {
		xmuxClient.LeftRequests.Store(x)
	}
	if x := m.xmuxConfig.GetNormalizedHMaxReusableSecs().Rand(); x > 0 {
		xmuxClient.UnreusableAt = time.Now().Add(time.Duration(x) * time.Second)
	}
	m.xmuxClients = append(m.xmuxClients, xmuxClient)
	return xmuxClient, nil
}

func (m *XmuxManager) GetXmuxClient(ctx context.Context) (*XmuxClient, error) {
	m.mx.Lock()
	defer m.mx.Unlock()

	for i := 0; i < len(m.xmuxClients); {
		xmuxClient := m.xmuxClients[i]
		if xmuxClient.XmuxConn.IsClosed() ||
			xmuxClient.leftUsage == 0 ||
			xmuxClient.LeftRequests.Load() <= 0 ||
			(xmuxClient.UnreusableAt != time.Time{} && time.Now().After(xmuxClient.UnreusableAt)) {
			// Remove from slice
			m.xmuxClients = append(m.xmuxClients[:i], m.xmuxClients[i+1:]...)
		} else {
			i++
		}
	}

	if len(m.xmuxClients) == 0 {
		return m.newXmuxClient(ctx)
	}

	if m.connections > 0 && len(m.xmuxClients) < int(m.connections) {
		return m.newXmuxClient(ctx)
	}

	var candidates []*XmuxClient
	if m.concurrency > 0 {
		for _, xmuxClient := range m.xmuxClients {
			if xmuxClient.OpenUsage.Load() < m.concurrency {
				candidates = append(candidates, xmuxClient)
			}
		}
	} else {
		candidates = m.xmuxClients
	}

	if len(candidates) == 0 {
		return m.newXmuxClient(ctx)
	}

	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(candidates))))
	xmuxClient := candidates[idx.Int64()]
	if xmuxClient.leftUsage > 0 {
		xmuxClient.leftUsage -= 1
	}
	return xmuxClient, nil
}
