package xhttp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http/httptrace"
	"sync"
	"sync/atomic"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/log"
)

type DialerClient interface {
	IsClosed() bool
	OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, net.Addr, net.Addr, error)
	PostPacket(context.Context, string, string, string, []byte) error
}

type DefaultDialerClient struct {
	transportConfig *SplitHTTPConfig
	client          *http.Client
	closed          atomic.Bool
	httpVersion     string
	uploadRawPool   *sync.Pool
	dialUploadConn  func(ctx context.Context) (net.Conn, error)
}

func (c *DefaultDialerClient) IsClosed() bool {
	return c.closed.Load()
}

func (c *DefaultDialerClient) OpenStream(ctx context.Context, url string, sessionID string, body io.Reader, uploadOnly bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	method := http.MethodGet
	if body != nil {
		method = c.transportConfig.GetNormalizedUplinkHTTPMethod()
	}
	stage := "stream-down"
	if body != nil {
		stage = "stream-one"
		if uploadOnly {
			stage = "stream-up"
		}
	}

	gotConn := make(chan struct{})
	var gotConnOnce sync.Once
	closeGotConn := func() {
		gotConnOnce.Do(func() {
			close(gotConn)
		})
	}

	var remoteAddr net.Addr
	var localAddr net.Addr
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			remoteAddr = connInfo.Conn.RemoteAddr()
			localAddr = connInfo.Conn.LocalAddr()
			closeGotConn()
		},
	})
	meta := connTelemetry{localAddr: "unknown", remoteAddr: "unknown"}

	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx), method, url, body)
	if err != nil {
		return nil, nil, nil, err
	}
	c.transportConfig.FillStreamRequest(req, sessionID)

	reader := &WaitReadCloser{Wait: make(chan struct{})}
	go func() {
		client := c.client
		if uploadOnly && c.httpVersion == "1.1" && c.dialUploadConn != nil {
			client = &http.Client{
				Transport: &http.Transport{
					ForceAttemptHTTP2: false,
					DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return c.dialUploadConn(ctx)
					},
					DisableKeepAlives: true,
				},
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			if !uploadOnly {
				c.closed.Store(true)
			}
			if localAddr != nil {
				meta.localAddr = localAddr.String()
			}
			if remoteAddr != nil {
				meta.remoteAddr = remoteAddr.String()
			}
			if c.transportConfig.RequestLog {
				log.Infoln("splithttp[%s-resp] err=%v local=%s remote=%s", stage, err, meta.localAddr, meta.remoteAddr)
			}
			closeGotConn()
			_ = reader.Close()
			return
		}
		if localAddr != nil {
			meta.localAddr = localAddr.String()
		}
		if remoteAddr != nil {
			meta.remoteAddr = remoteAddr.String()
		}
		logResponse(c.transportConfig, stage, resp, sessionID, "", meta)
		if uploadOnly || resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			closeGotConn()
			_ = reader.Close()
			return
		}
		reader.Set(resp.Body)
		closeGotConn()
	}()

	<-gotConn
	return reader, remoteAddr, localAddr, nil
}

func (c *DefaultDialerClient) PostPacket(ctx context.Context, url string, sessionID string, seqStr string, payload []byte) error {
	method := c.transportConfig.GetNormalizedUplinkHTTPMethod()
	var remoteAddr net.Addr
	var localAddr net.Addr
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			remoteAddr = connInfo.Conn.RemoteAddr()
			localAddr = connInfo.Conn.LocalAddr()
		},
	})
	meta := connTelemetry{localAddr: "unknown", remoteAddr: "unknown"}

	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx), method, url, nil)
	if err != nil {
		return err
	}
	c.transportConfig.FillPacketRequest(req, sessionID, seqStr, payload)

	if c.httpVersion != "1.1" {
		resp, err := c.client.Do(req)
		if err != nil {
			c.closed.Store(true)
			if localAddr != nil {
				meta.localAddr = localAddr.String()
			}
			if remoteAddr != nil {
				meta.remoteAddr = remoteAddr.String()
			}
			if c.transportConfig.RequestLog {
				log.Infoln("splithttp[packet-up-resp] err=%v session=%s seq=%s local=%s remote=%s", err, sessionID, seqStr, meta.localAddr, meta.remoteAddr)
			}
			return err
		}
		if localAddr != nil {
			meta.localAddr = localAddr.String()
		}
		if remoteAddr != nil {
			meta.remoteAddr = remoteAddr.String()
		}
		logResponse(c.transportConfig, "packet-up", resp, sessionID, seqStr, meta)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("packet-up bad status: %d", resp.StatusCode)
		}
		return nil
	}

	requestBuff := new(bytes.Buffer)
	requestBuff.Grow(512 + int(req.ContentLength))
	if err := req.Write(requestBuff); err != nil {
		return err
	}

	var uploadConn any
	var h1UploadConn *H1Conn

	for {
		uploadConn = c.uploadRawPool.Get()
		newConnection := uploadConn == nil
		if newConnection {
			newConn, err := c.dialUploadConn(context.WithoutCancel(ctx))
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
					c.closed.Store(true)
					if c.transportConfig.RequestLog {
						log.Infoln("splithttp[packet-up-resp] err=%v session=%s seq=%s local=%s remote=%s", err, sessionID, seqStr, h1UploadConn.LocalAddr(), h1UploadConn.RemoteAddr())
					}
					return fmt.Errorf("packet-up read response failed: %w", err)
				}
				logResponse(c.transportConfig, "packet-up", resp, sessionID, seqStr, connTelemetry{
					localAddr:  h1UploadConn.LocalAddr().String(),
					remoteAddr: h1UploadConn.RemoteAddr().String(),
				})
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					return fmt.Errorf("packet-up bad status: %d", resp.StatusCode)
				}
			}
		}

		_, err = h1UploadConn.Write(requestBuff.Bytes())
		if err == nil {
			break
		} else if newConnection {
			return err
		}
	}

	c.uploadRawPool.Put(uploadConn)
	return nil
}
