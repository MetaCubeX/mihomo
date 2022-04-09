package mitm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/Dreamacro/clash/common/cache"
	N "github.com/Dreamacro/clash/common/net"
	C "github.com/Dreamacro/clash/constant"
	H "github.com/Dreamacro/clash/listener/http"
)

func HandleConn(c net.Conn, opt *Option, in chan<- C.ConnContext, cache *cache.LruCache[string, bool]) {
	var (
		clientIP   = netip.MustParseAddrPort(c.RemoteAddr().String()).Addr()
		sourceAddr net.Addr
		serverConn *N.BufferedConn
		connState  *tls.ConnectionState
	)

	defer func() {
		if serverConn != nil {
			_ = serverConn.Close()
		}
	}()

	conn := N.NewBufferedConn(c)

	trusted := cache == nil // disable authenticate if cache is nil
	if !trusted {
		trusted = clientIP.IsLoopback() || clientIP.IsUnspecified()
	}

readLoop:
	for {
		// use SetReadDeadline instead of Proxy-Connection keep-alive
		if err := conn.SetReadDeadline(time.Now().Add(65 * time.Second)); err != nil {
			break
		}

		request, err := H.ReadRequest(conn.Reader())
		if err != nil {
			break
		}

		var response *http.Response

		session := newSession(conn, request, response)

		sourceAddr = parseSourceAddress(session.request, conn.RemoteAddr(), sourceAddr)
		session.request.RemoteAddr = sourceAddr.String()

		if !trusted {
			session.response = H.Authenticate(session.request, cache)

			trusted = session.response == nil
		}

		if trusted {
			if session.request.Method == http.MethodConnect {
				if session.request.ProtoMajor > 1 {
					session.request.ProtoMajor = 1
					session.request.ProtoMinor = 1
				}

				// Manual writing to support CONNECT for http 1.0 (workaround for uplay client)
				if _, err = fmt.Fprintf(session.conn, "HTTP/%d.%d %03d %s\r\n\r\n", session.request.ProtoMajor, session.request.ProtoMinor, http.StatusOK, "Connection established"); err != nil {
					handleError(opt, session, err)
					break // close connection
				}

				if strings.HasSuffix(session.request.URL.Host, ":80") {
					goto readLoop
				}

				b, err1 := conn.Peek(1)
				if err1 != nil {
					handleError(opt, session, err1)
					break // close connection
				}

				// TLS handshake.
				if b[0] == 0x16 {
					tlsConn := tls.Server(conn, opt.CertConfig.NewTLSConfigForHost(session.request.URL.Hostname()))

					ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
					// handshake with the local client
					if err = tlsConn.HandshakeContext(ctx); err != nil {
						cancel()
						session.response = session.NewErrorResponse(fmt.Errorf("handshake failed: %w", err))
						_ = writeResponse(session, false)
						break // close connection
					}
					cancel()

					cs := tlsConn.ConnectionState()
					connState = &cs

					conn = N.NewBufferedConn(tlsConn)
				}

				if strings.HasSuffix(session.request.URL.Host, ":443") {
					goto readLoop
				}

				if conn.SetReadDeadline(time.Now().Add(time.Second)) != nil {
					break
				}

				buf, err2 := conn.Peek(7)
				if err2 != nil {
					if err2 != bufio.ErrBufferFull && !os.IsTimeout(err2) {
						handleError(opt, session, err2)
						break // close connection
					}
				}

				// others protocol over tcp
				if !isHTTPTraffic(buf) {
					if connState != nil {
						session.request.TLS = connState
					}

					serverConn, err = getServerConn(serverConn, session.request, sourceAddr, in)
					if err != nil {
						break
					}

					if conn.SetReadDeadline(time.Time{}) != nil {
						break
					}

					N.Relay(serverConn, conn)
					return // hijack connection
				}

				goto readLoop
			}

			prepareRequest(connState, session.request)

			// hijack api
			if session.request.URL.Hostname() == opt.ApiHost {
				if err = handleApiRequest(session, opt); err != nil {
					handleError(opt, session, err)
				}
				break
			}

			// forward websocket
			if isWebsocketRequest(request) {
				serverConn, err = getServerConn(serverConn, session.request, sourceAddr, in)
				if err != nil {
					break
				}

				session.request.RequestURI = ""
				if session.response = H.HandleUpgradeY(conn, serverConn, request, in); session.response == nil {
					return // hijack connection
				}
			}

			if session.response == nil {
				H.RemoveHopByHopHeaders(session.request.Header)
				H.RemoveExtraHTTPHostPort(session.request)

				// hijack custom request and write back custom response if necessary
				newReq, newRes := opt.Handler.HandleRequest(session)
				if newReq != nil {
					session.request = newReq
				}
				if newRes != nil {
					session.response = newRes

					if err = writeResponse(session, false); err != nil {
						handleError(opt, session, err)
						break
					}
					continue
				}

				session.request.RequestURI = ""

				if session.request.URL.Host == "" {
					session.response = session.NewErrorResponse(ErrInvalidURL)
				} else {
					serverConn, err = getServerConn(serverConn, session.request, sourceAddr, in)
					if err != nil {
						break
					}

					// send the request to remote server
					err = session.request.Write(serverConn)
					if err != nil {
						break
					}

					session.response, err = http.ReadResponse(serverConn.Reader(), request)
					if err != nil {
						break
					}
				}
			}
		}

		if err = writeResponseWithHandler(session, opt); err != nil {
			handleError(opt, session, err)
			break // close connection
		}
	}

	_ = conn.Close()
}

func writeResponseWithHandler(session *Session, opt *Option) error {
	res := opt.Handler.HandleResponse(session)
	if res != nil {
		session.response = res
	}

	return writeResponse(session, true)
}

func writeResponse(session *Session, keepAlive bool) error {
	H.RemoveHopByHopHeaders(session.response.Header)

	if keepAlive {
		session.response.Header.Set("Connection", "keep-alive")
		session.response.Header.Set("Keep-Alive", "timeout=60")
	}

	return session.writeResponse()
}

func handleApiRequest(session *Session, opt *Option) error {
	if opt.CertConfig != nil && strings.ToLower(session.request.URL.Path) == "/cert.crt" {
		b := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: opt.CertConfig.GetCA().Raw,
		})

		session.response = session.NewResponse(http.StatusOK, bytes.NewReader(b))

		session.response.Close = true
		session.response.Header.Set("Content-Type", "application/x-x509-ca-cert")
		session.response.ContentLength = int64(len(b))

		return session.writeResponse()
	}

	b := `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>Clash MITM Proxy Services - 404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL %s was not found on this server.</p>
</body></html>
`

	if opt.Handler.HandleApiRequest(session) {
		return nil
	}

	b = fmt.Sprintf(b, session.request.URL.Path)

	session.response = session.NewResponse(http.StatusNotFound, bytes.NewReader([]byte(b)))
	session.response.Close = true
	session.response.Header.Set("Content-Type", "text/html;charset=utf-8")
	session.response.ContentLength = int64(len(b))

	return session.writeResponse()
}

func handleError(opt *Option, session *Session, err error) {
	if session.response != nil {
		defer func() {
			_, _ = io.Copy(io.Discard, session.response.Body)
			_ = session.response.Body.Close()
		}()
	}
	opt.Handler.HandleError(session, err)
}

func prepareRequest(connState *tls.ConnectionState, request *http.Request) {
	host := request.Header.Get("Host")
	if host != "" {
		request.Host = host
	}

	if request.URL.Host == "" {
		request.URL.Host = request.Host
	}

	if request.URL.Scheme == "" {
		request.URL.Scheme = "http"
	}

	if connState != nil {
		request.TLS = connState
		request.URL.Scheme = "https"
	}

	if request.Header.Get("Accept-Encoding") != "" {
		request.Header.Set("Accept-Encoding", "gzip")
	}
}

func parseSourceAddress(req *http.Request, connSource, source net.Addr) net.Addr {
	if source != nil {
		return source
	}

	sourceAddress := req.Header.Get("Origin-Request-Source-Address")
	if sourceAddress == "" {
		return connSource
	}

	req.Header.Del("Origin-Request-Source-Address")

	addrPort, err := netip.ParseAddrPort(sourceAddress)
	if err != nil {
		return connSource
	}

	return &net.TCPAddr{
		IP:   addrPort.Addr().AsSlice(),
		Port: int(addrPort.Port()),
	}
}

func isWebsocketRequest(req *http.Request) bool {
	return strings.EqualFold(req.Header.Get("Connection"), "Upgrade") && strings.EqualFold(req.Header.Get("Upgrade"), "websocket")
}

func isHTTPTraffic(buf []byte) bool {
	method, _, _ := strings.Cut(string(buf), " ")
	return validMethod(method)
}
