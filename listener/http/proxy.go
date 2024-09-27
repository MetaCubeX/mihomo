package http

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/auth"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type bodyWrapper struct {
	io.ReadCloser
	once     sync.Once
	onHitEOF func()
}

func (b *bodyWrapper) Read(p []byte) (n int, err error) {
	n, err = b.ReadCloser.Read(p)
	if err == io.EOF && b.onHitEOF != nil {
		b.once.Do(b.onHitEOF)
	}
	return n, err
}

func HandleConn(c net.Conn, tunnel C.Tunnel, store auth.AuthStore, additions ...inbound.Addition) {
	additions = append(additions, inbound.Placeholder) // Add a placeholder for InUser
	inUserIdx := len(additions) - 1
	client := newClient(c, tunnel, additions)
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peekMutex := sync.Mutex{}

	conn := N.NewBufferedConn(c)

	authenticator := store.Authenticator()
	keepAlive := true
	trusted := authenticator == nil // disable authenticate if lru is nil
	lastUser := ""

	for keepAlive {
		peekMutex.Lock()
		request, err := ReadRequest(conn.Reader())
		peekMutex.Unlock()
		if err != nil {
			break
		}

		request.RemoteAddr = conn.RemoteAddr().String()

		keepAlive = strings.TrimSpace(strings.ToLower(request.Header.Get("Proxy-Connection"))) == "keep-alive"

		var resp *http.Response

		var user string
		resp, user = authenticate(request, authenticator) // always call authenticate function to get user
		trusted = trusted || resp == nil
		additions[inUserIdx] = inbound.WithInUser(user)

		if trusted {
			if request.Method == http.MethodConnect {
				// Manual writing to support CONNECT for http 1.0 (workaround for uplay client)
				if _, err = fmt.Fprintf(conn, "HTTP/%d.%d %03d %s\r\n\r\n", request.ProtoMajor, request.ProtoMinor, http.StatusOK, "Connection established"); err != nil {
					break // close connection
				}

				tunnel.HandleTCPConn(inbound.NewHTTPS(request, conn, additions...))

				return // hijack connection
			}

			host := request.Header.Get("Host")
			if host != "" {
				request.Host = host
			}

			request.RequestURI = ""

			if isUpgradeRequest(request) {
				handleUpgrade(conn, request, tunnel, additions...)

				return // hijack connection
			}

			// ensure there is a client with correct additions
			// when the authenticated user changed, outbound client should close idle connections
			if user != lastUser {
				client.CloseIdleConnections()
				lastUser = user
			}

			removeHopByHopHeaders(request.Header)
			removeExtraHTTPHostPort(request)

			if request.URL.Scheme == "" || request.URL.Host == "" {
				resp = responseWith(request, http.StatusBadRequest)
			} else {
				request = request.WithContext(ctx)

				startBackgroundRead := func() {
					go func() {
						peekMutex.Lock()
						defer peekMutex.Unlock()
						_, err := conn.Peek(1)
						if err != nil {
							cancel()
						}
					}()
				}
				if request.Body == nil || request.Body == http.NoBody {
					startBackgroundRead()
				} else {
					request.Body = &bodyWrapper{ReadCloser: request.Body, onHitEOF: startBackgroundRead}
				}
				resp, err = client.Do(request)
				if err != nil {
					resp = responseWith(request, http.StatusBadGateway)
				}
			}

			removeHopByHopHeaders(resp.Header)
		}

		if keepAlive {
			resp.Header.Set("Proxy-Connection", "keep-alive")
			resp.Header.Set("Connection", "keep-alive")
			resp.Header.Set("Keep-Alive", "timeout=4")
		}

		resp.Close = !keepAlive

		err = resp.Write(conn)
		if err != nil {
			break // close connection
		}
	}

	_ = conn.Close()
}

func authenticate(request *http.Request, authenticator auth.Authenticator) (resp *http.Response, user string) {
	credential := parseBasicProxyAuthorization(request)
	if credential == "" && authenticator != nil {
		resp = responseWith(request, http.StatusProxyAuthRequired)
		resp.Header.Set("Proxy-Authenticate", "Basic")
		return
	}
	user, pass, err := decodeBasicProxyAuthorization(credential)
	authed := authenticator == nil || (err == nil && authenticator.Verify(user, pass))
	if !authed {
		log.Infoln("Auth failed from %s", request.RemoteAddr)
		return responseWith(request, http.StatusForbidden), user
	}
	log.Debugln("Auth success from %s -> %s", request.RemoteAddr, user)
	return
}

func responseWith(request *http.Request, statusCode int) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Proto:      request.Proto,
		ProtoMajor: request.ProtoMajor,
		ProtoMinor: request.ProtoMinor,
		Header:     http.Header{},
	}
}
