package splithttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/mihomo/log"
	"golang.org/x/net/http2"
)

type DialerClient interface {
	IsClosed() bool
	OpenStream(context.Context, string, io.Reader, bool) (io.ReadCloser, net.Addr, net.Addr, error)
	PostPacket(context.Context, string, io.Reader, int64) error
}

type DefaultDialerClient struct {
	transportConfig *Config
	client          *http.Client
	closed          bool
	httpVersion     string
	uploadRawPool   *sync.Pool
	dialUploadConn  func(ctxInner context.Context) (net.Conn, error)
}

func (c *DefaultDialerClient) IsClosed() bool {
	return c.closed
}

func (c *DefaultDialerClient) OpenStream(ctx context.Context, url string, body io.Reader, uploadOnly bool) (wrc io.ReadCloser, remoteAddr, localAddr net.Addr, err error) {
	gotConn := make(chan struct{})
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			remoteAddr = connInfo.Conn.RemoteAddr()
			localAddr = connInfo.Conn.LocalAddr()
			close(gotConn)
		},
	})

	method := "GET"
	if body != nil {
		method = "POST"
	}
	req, _ := http.NewRequestWithContext(ctx, method, url, body)
	req.Header = c.transportConfig.GetRequestHeader(url)
	if method == "POST" && !c.transportConfig.NoGRPCHeader {
		req.Header.Set("Content-Type", "application/grpc")
	}

	wrcWrapper := &WaitReadCloser{Wait: make(chan struct{})}
	wrc = wrcWrapper
	
	go func() {
		resp, err := c.client.Do(req)
		if err != nil {
			if !uploadOnly {
				c.closed = true
				log.Debugln("failed to %s %s: %s", method, url, err)
			}
			// If GotConn didn't fire (e.g. connection error), we need to unblock the caller
			select {
			case <-gotConn:
			default:
				close(gotConn)
			}
			wrcWrapper.Close()
			return
		}
		if resp.StatusCode != 200 && !uploadOnly {
			log.Debugln("unexpected status %d", resp.StatusCode)
		}
		if resp.StatusCode != 200 || uploadOnly {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			wrcWrapper.Close()
			return
		}
		wrcWrapper.Set(resp.Body)
	}()

	<-gotConn
	return
}

func (c *DefaultDialerClient) PostPacket(ctx context.Context, url string, body io.Reader, contentLength int64) error {
	req, err := http.NewRequestWithContext(ctx, "POST", url, body)
	if err != nil {
		return err
	}
	req.ContentLength = contentLength
	req.Header = c.transportConfig.GetRequestHeader(url)

	if c.httpVersion != "1.1" {
		resp, err := c.client.Do(req)
		if err != nil {
			c.closed = true
			return err
		}

		io.Copy(io.Discard, resp.Body)
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return fmt.Errorf("bad status code: %s", resp.Status)
		}
	} else {
		requestBuff := new(bytes.Buffer)
		// req.Write in standard lib writes the wire format. 
		// Check if Xray's req.Write usage implies standard http.Request.Write.
		// Yes, Xray uses common.Must(req.Write(requestBuff))
		if err := req.Write(requestBuff); err != nil {
			return err
		}

		var uploadConn any
		var h1UploadConn *H1Conn

		for {
			uploadConn = c.uploadRawPool.Get()
			newConnection := uploadConn == nil
			if newConnection {
				newConn, err := c.dialUploadConn(ctx)
				if err != nil {
					return err
				}
				h1UploadConn = NewH1Conn(newConn)
				uploadConn = h1UploadConn
			} else {
				h1UploadConn = uploadConn.(*H1Conn)

				if h1UploadConn.UnreadedResponsesCount > 0 {
					resp, err := http.ReadResponse(h1UploadConn.RespBufReader, req)
					if err != nil {
						c.closed = true
						return fmt.Errorf("error while reading response: %s", err.Error())
					}
					io.Copy(io.Discard, resp.Body)
					defer resp.Body.Close()
					if resp.StatusCode != 200 {
						return fmt.Errorf("got non-200 error response code: %d", resp.StatusCode)
					}
				}
			}

			_, err := h1UploadConn.Write(requestBuff.Bytes())
			if err == nil {
				break
			} else if newConnection {
				return err
			}
		}

		c.uploadRawPool.Put(uploadConn)
	}

	return nil
}

type WaitReadCloser struct {
	Wait chan struct{}
	io.ReadCloser
	mu sync.Mutex
}

func (w *WaitReadCloser) Set(rc io.ReadCloser) {
	w.mu.Lock()
	w.ReadCloser = rc
	w.mu.Unlock()
	
	// Avoid panic if closed twice
	defer func() { recover() }()
	close(w.Wait)
}

func (w *WaitReadCloser) Read(b []byte) (int, error) {
	if w.ReadCloser == nil {
		if <-w.Wait; w.ReadCloser == nil {
			return 0, io.ErrClosedPipe
		}
	}
	return w.ReadCloser.Read(b)
}

func (w *WaitReadCloser) Close() error {
	w.mu.Lock()
	rc := w.ReadCloser
	w.mu.Unlock()
	
	if rc != nil {
		return rc.Close()
	}
	defer func() { recover() }()
	close(w.Wait)
	return nil
}

type DialFn func(ctx context.Context, network, addr string) (net.Conn, error)

type dialerConf struct {
	Host string // used as key
	*Config
}

var (
	globalDialerMap    map[dialerConf]*XmuxManager
	globalDialerAccess sync.Mutex
)

func decideHTTPVersion(tlsConfig *tls.Config) string {
	if tlsConfig == nil {
		return "1.1"
	}
	if len(tlsConfig.NextProtos) != 1 {
		return "2"
	}
	if tlsConfig.NextProtos[0] == "http/1.1" {
		return "1.1"
	}
	if tlsConfig.NextProtos[0] == "h3" {
		return "3"
	}
	return "2"
}

func getHTTPClient(ctx context.Context, dialFn DialFn, config *Config, tlsConfig *tls.Config) (DialerClient, *XmuxClient) {
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()

	if globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]*XmuxManager)
	}

	// Use Host and Config pointer as key. 
	// Note: Config might be different instance with same content. 
	// Ideally we should use value semantics or consistent ID. 
	// For now using Host and Config pointer.
	key := dialerConf{config.Host, config}

	xmuxManager, found := globalDialerMap[key]

	if !found {
		var xmuxConfig XmuxConfig
		if config.Xmux != nil {
			xmuxConfig = *config.Xmux
		}

		xmuxManager = NewXmuxManager(xmuxConfig, func() XmuxConn {
			return createHTTPClient(dialFn, config, tlsConfig)
		})
		globalDialerMap[key] = xmuxManager
	}

	xmuxClient := xmuxManager.GetXmuxClient(ctx)
	return xmuxClient.XmuxConn.(DialerClient), xmuxClient
}

func createHTTPClient(dialFn DialFn, config *Config, tlsConfig *tls.Config) DialerClient {
	httpVersion := decideHTTPVersion(tlsConfig)

	dialContext := func(ctxInner context.Context) (net.Conn, error) {
		// network and addr are not used by dialFn in this context usually, 
		// because dialFn is already bound to a destination in vless.
		// But DialFn signature has network/addr.
		// In vless.go, dialFn is `func(ctx, network, addr)`.
		return dialFn(ctxInner, "tcp", config.Host)
	}

	var keepAlivePeriod time.Duration
	if config.Xmux != nil {
		keepAlivePeriod = time.Duration(config.Xmux.HKeepAlivePeriod) * time.Second
	}

	var transport http.RoundTripper

	if httpVersion == "3" {
		// quic-go setup
		// H3 support disabled for now to avoid dependency issues
		return nil
	} else if httpVersion == "2" {
		if keepAlivePeriod == 0 {
			keepAlivePeriod = 30 * time.Second // Default
		}
		transport = &http2.Transport{
			DialTLSContext: func(ctxInner context.Context, network string, addr string, cfg *tls.Config) (net.Conn, error) {
				// We ignore cfg here as we use the one from creation or handle TLS in dialFn?
				// Actually dialContext should return a TLS connection if TLS is enabled?
				// In Xray `dialContext` returns `tls.Client(conn)`.
				// Here `dialFn` from vless seems to return plain TCP usually, then wrapped.
				
				conn, err := dialContext(ctxInner)
				if err != nil {
					return nil, err
				}
				
				if tlsConfig != nil {
					// Wrap with TLS
					conn = tls.Client(conn, tlsConfig)
					// Handshake?
				}
				return conn, nil
			},
			IdleConnTimeout: 90 * time.Second,
			ReadIdleTimeout: keepAlivePeriod,
		}
	} else {
		httpDialContext := func(ctxInner context.Context, network string, addr string) (net.Conn, error) {
			conn, err := dialContext(ctxInner)
			if err != nil {
				return nil, err
			}
			if tlsConfig != nil {
				conn = tls.Client(conn, tlsConfig)
			}
			return conn, nil
		}

		transport = &http.Transport{
			DialTLSContext:  httpDialContext,
			DialContext:     httpDialContext,
			IdleConnTimeout: 90 * time.Second,
			DisableKeepAlives: true,
		}
	}

	client := &DefaultDialerClient{
		transportConfig: config,
		client: &http.Client{
			Transport: transport,
		},
		httpVersion:    httpVersion,
		uploadRawPool:  &sync.Pool{},
		dialUploadConn: dialContext,
	}

	return client
}

func Dial(ctx context.Context, dialFn DialFn, config *Config, tlsConfig *tls.Config) (net.Conn, error) {
	httpVersion := decideHTTPVersion(tlsConfig)
	
	requestURL := url.URL{}
	if tlsConfig != nil {
		requestURL.Scheme = "https"
	} else {
		requestURL.Scheme = "http"
	}
	requestURL.Host = config.Host
	if requestURL.Host == "" && tlsConfig != nil {
		requestURL.Host = tlsConfig.ServerName
	}

	sessionId, _ := uuid.NewV4()
	requestURL.Path = config.GetNormalizedPath() + sessionId.String()
	requestURL.RawQuery = config.GetNormalizedQuery()

	httpClient, xmuxClient := getHTTPClient(ctx, dialFn, config, tlsConfig)

	mode := config.Mode
	if mode == "" || mode == "auto" {
		mode = "packet-up"
	}

	log.Debugln("XHTTP is dialing to %s, mode %s, HTTP version %s, host %s", config.Host, mode, httpVersion, requestURL.Host)

	if xmuxClient != nil {
		xmuxClient.OpenUsage.Add(1)
	}
	
	var closed atomic.Int32
	reader, writer := io.Pipe() // Use io.Pipe instead of Xray pipe
	
	conn := &splitConn{
		writer: writer,
		onClose: func() {
			if closed.Add(1) > 1 {
				return
			}
			if xmuxClient != nil {
				xmuxClient.OpenUsage.Add(-1)
			}
		},
	}
	
	var err error
	if mode == "stream-one" {
		requestURL.Path = config.GetNormalizedPath()
		if xmuxClient != nil {
			xmuxClient.LeftRequests.Add(-1)
		}
		conn.reader, conn.remoteAddr, conn.localAddr, err = httpClient.OpenStream(ctx, requestURL.String(), reader, false)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
	
	// Split mode (stream-up/packet-up + stream-down)
	
	// Stream Down
	// We need a separate client for download? Xray handles DownloadSettings.
	// For simplicity, use the same client for now or if DownloadSettings is present, create another.
	// Assuming same config for now.
	httpClientDown := httpClient
	if config.DownloadSettings != nil {
		// TODO: Handle separate download settings
		// For now use same client
	}
	
	if xmuxClient != nil {
		xmuxClient.LeftRequests.Add(-1)
	}
	conn.reader, conn.remoteAddr, conn.localAddr, err = httpClientDown.OpenStream(ctx, requestURL.String(), nil, false)
	if err != nil {
		return nil, err
	}
	
	if mode == "stream-up" {
		if xmuxClient != nil {
			xmuxClient.LeftRequests.Add(-1)
		}
		_, _, _, err = httpClient.OpenStream(ctx, requestURL.String(), reader, true)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
	
	// packet-up
	scMaxEachPostBytes := config.GetNormalizedScMaxEachPostBytes()
	scMinPostsIntervalMs := config.GetNormalizedScMinPostsIntervalMs()
	
	// We need a buffer to read from pipe and chunk it
	maxUploadSize := scMaxEachPostBytes.rand()
	
	go func() {
		var seq int64
		var lastWrite time.Time
		buf := make([]byte, maxUploadSize)
		
		for {
			wroteRequest := make(chan struct{})
			ctxTrace := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
				WroteRequest: func(httptrace.WroteRequestInfo) {
					close(wroteRequest)
				},
			})
			
			url := requestURL
			url.Path += "/" + strconv.FormatInt(seq, 10)
			seq++
			
			if scMinPostsIntervalMs.From > 0 {
				time.Sleep(time.Duration(scMinPostsIntervalMs.rand())*time.Millisecond - time.Since(lastWrite))
			}
			
			// Read from pipe
			n, err := reader.Read(buf)
			if err != nil {
				break
			}
			
			lastWrite = time.Now()
			
			if xmuxClient != nil && (xmuxClient.LeftRequests.Add(-1) <= 0 ||
				(xmuxClient.UnreusableAt != time.Time{} && lastWrite.After(xmuxClient.UnreusableAt))) {
				httpClient, xmuxClient = getHTTPClient(ctx, dialFn, config, tlsConfig)
			}
			
			chunk := buf[:n]
			// Copy chunk because buf is reused
			chunkCopy := make([]byte, n)
			copy(chunkCopy, chunk)
			
			go func() {
				// PostPacket expects io.Reader
				err := httpClient.PostPacket(
					ctxTrace,
					url.String(),
					bytes.NewReader(chunkCopy),
					int64(n),
				)
				
				// If WroteRequest wasn't called (error), close channel
				select {
				case <-wroteRequest:
				default:
					close(wroteRequest)
				}
				
				if err != nil {
					log.Debugln("failed to send upload: %v", err)
					reader.CloseWithError(err)
				}
			}()
			
			if _, ok := httpClient.(*DefaultDialerClient); ok {
				<-wroteRequest
			}
		}
	}()
	
	return conn, nil
}
