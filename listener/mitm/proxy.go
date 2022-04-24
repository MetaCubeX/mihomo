package mitm

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/Dreamacro/clash/common/cache"
	N "github.com/Dreamacro/clash/common/net"
	C "github.com/Dreamacro/clash/constant"
	H "github.com/Dreamacro/clash/listener/http"
)

func HandleConn(c net.Conn, opt *Option, in chan<- C.ConnContext, cache *cache.Cache[string, bool]) {
	var (
		source net.Addr
		client *http.Client
	)

	defer func() {
		if client != nil {
			client.CloseIdleConnections()
		}
	}()

startOver:
	var conn *N.BufferedConn
	if bufConn, ok := c.(*N.BufferedConn); ok {
		conn = bufConn
	} else {
		conn = N.NewBufferedConn(c)
	}

	trusted := cache == nil // disable authenticate if cache is nil

readLoop:
	for {
		// use SetReadDeadline instead of Proxy-Connection keep-alive
		if err := conn.SetReadDeadline(time.Now().Add(65 * time.Second)); err != nil {
			break readLoop
		}

		request, err := H.ReadRequest(conn.Reader())
		if err != nil {
			break readLoop
		}

		var response *http.Response

		session := newSession(conn, request, response)

		source = parseSourceAddress(session.request, c.RemoteAddr(), source)
		session.request.RemoteAddr = source.String()

		if !trusted {
			session.response = H.Authenticate(session.request, cache)

			trusted = session.response == nil
		}

		if trusted {
			if session.request.Method == http.MethodConnect {
				// Manual writing to support CONNECT for http 1.0 (workaround for uplay client)
				if _, err = fmt.Fprintf(session.conn, "HTTP/%d.%d %03d %s\r\n\r\n", session.request.ProtoMajor, session.request.ProtoMinor, http.StatusOK, "Connection established"); err != nil {
					handleError(opt, session, err)
					break readLoop // close connection
				}

				if strings.HasSuffix(session.request.URL.Host, ":80") {
					goto readLoop
				}

				b, err := conn.Peek(1)
				if err != nil {
					handleError(opt, session, err)
					break readLoop // close connection
				}

				// TLS handshake.
				if b[0] == 0x16 {
					tlsConn := tls.Server(conn, opt.CertConfig.NewTLSConfigForHost(session.request.URL.Hostname()))

					// Handshake with the local client
					if err = tlsConn.Handshake(); err != nil {
						session.response = session.NewErrorResponse(fmt.Errorf("handshake failed: %w", err))
						_ = writeResponse(session, false)
						break readLoop // close connection
					}

					c = tlsConn
				} else {
					c = conn
				}

				goto startOver
			}

			prepareRequest(c, session.request)

			H.RemoveHopByHopHeaders(session.request.Header)
			H.RemoveExtraHTTPHostPort(session.request)

			// hijack api
			if session.request.URL.Hostname() == opt.ApiHost {
				if err = handleApiRequest(session, opt); err != nil {
					handleError(opt, session, err)
					break readLoop
				}
				return
			}

			// hijack custom request and write back custom response if necessary
			if opt.Handler != nil {
				newReq, newRes := opt.Handler.HandleRequest(session)
				if newReq != nil {
					session.request = newReq
				}
				if newRes != nil {
					session.response = newRes

					if err = writeResponse(session, false); err != nil {
						handleError(opt, session, err)
						break readLoop
					}
					return
				}
			}

			session.request.RequestURI = ""

			if session.request.URL.Host == "" {
				session.response = session.NewErrorResponse(ErrInvalidURL)
			} else {
				client = newClientBySourceAndUserAgentIfNil(client, session.request, source, in)

				// send the request to remote server
				session.response, err = client.Do(session.request)

				if err != nil {
					handleError(opt, session, err)
					session.response = session.NewErrorResponse(err)
					if errors.Is(err, ErrCertUnsupported) || strings.Contains(err.Error(), "x509: ") {
						_ = writeResponse(session, false)
						break readLoop
					}
				}
			}
		}

		if err = writeResponseWithHandler(session, opt); err != nil {
			handleError(opt, session, err)
			break readLoop // close connection
		}
	}

	_ = conn.Close()
}

func writeResponseWithHandler(session *Session, opt *Option) error {
	if opt.Handler != nil {
		res := opt.Handler.HandleResponse(session)
		if res != nil {
			session.response = res
		}
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

	if opt.Handler != nil {
		if opt.Handler.HandleApiRequest(session) {
			return nil
		}
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
	if opt.Handler != nil {
		opt.Handler.HandleError(session, err)
	}
}

func prepareRequest(conn net.Conn, request *http.Request) {
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

	if tlsConn, ok := conn.(*tls.Conn); ok {
		cs := tlsConn.ConnectionState()
		request.TLS = &cs

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

func newClientBySourceAndUserAgentIfNil(cli *http.Client, req *http.Request, source net.Addr, in chan<- C.ConnContext) *http.Client {
	if cli != nil {
		return cli
	}

	return newClient(source, req.Header.Get("User-Agent"), in)
}
