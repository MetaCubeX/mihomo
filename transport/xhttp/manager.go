package xhttp

import (
	"sync"

	"github.com/metacubex/mihomo/log"
)

type h3ClientKey struct {
	dialAddr      string
	tlsServerName string
	host          string
	path          string
	query         string
}

var (
	h3ClientManagerMu sync.Mutex
	h3ClientManager   = map[h3ClientKey]*DefaultDialerClient{}
)

func getH3DialerClient(config *SplitHTTPConfig) DialerClient {
	key := h3ClientKey{
		dialAddr:      config.DialAddr,
		tlsServerName: config.TLSServerName,
		host:          config.Host,
		path:          config.GetNormalizedPath(),
		query:         config.GetNormalizedQuery(),
	}

	h3ClientManagerMu.Lock()
	defer h3ClientManagerMu.Unlock()

	if client, ok := h3ClientManager[key]; ok && !client.IsClosed() {
		log.Debugln("splithttp[h3-client] reuse dial=%s sni=%s host=%s path=%s", key.dialAddr, key.tlsServerName, key.host, key.path)
		return client
	}

	if client, ok := h3ClientManager[key]; ok && client.IsClosed() {
		log.Debugln("splithttp[h3-client] replace closed dial=%s sni=%s host=%s path=%s", key.dialAddr, key.tlsServerName, key.host, key.path)
	} else {
		log.Debugln("splithttp[h3-client] create dial=%s sni=%s host=%s path=%s", key.dialAddr, key.tlsServerName, key.host, key.path)
	}

	client := &DefaultDialerClient{
		transportConfig: config,
		client:          buildHTTP3Client(config),
		httpVersion:     "3",
		uploadRawPool:   &sync.Pool{},
	}
	h3ClientManager[key] = client
	return client
}
