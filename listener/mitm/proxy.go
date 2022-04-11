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
	"strconv"
	"strings"
	"time"

	"github.com/Dreamacro/clash/adapter/inbound"
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
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
	}

	var conn *N.BufferedConn
	if bufConn, ok := c.(*N.BufferedConn); ok {
		conn = bufConn
	} else {
		conn = N.NewBufferedConn(c)
	}

	trusted := cache == nil // disable authenticate if cache is nil

readLoop:
	for {
		err := conn.SetDeadline(time.Now().Add(30 * time.Second)) // use SetDeadline instead of Proxy-Connection keep-alive
		if err != nil {
			break readLoop
		}

		request, err := H.ReadRequest(conn.Reader())
		if err != nil {
			handleError(opt, nil, err)
			break readLoop
		}

		var response *http.Response

		session := newSession(conn, request, response)

		source = parseSourceAddress(session.request, c, source)
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

				if couldBeWithManInTheMiddleAttack(session.request.URL.Host, opt) {
					b := make([]byte, 1)
					if _, err = session.conn.Read(b); err != nil {
						handleError(opt, session, err)
						break readLoop // close connection
					}

					buff := make([]byte, session.conn.(*N.BufferedConn).Buffered())
					_, _ = session.conn.Read(buff)

					mrc := &multiReaderConn{
						Conn:   session.conn,
						reader: io.MultiReader(bytes.NewReader(b), bytes.NewReader(buff), session.conn),
					}

					// TLS handshake.
					if b[0] == 0x16 {
						// TODO serve by generic host name maybe better?
						tlsConn := tls.Server(mrc, opt.CertConfig.NewTLSConfigForHost(session.request.URL.Host))

						// Handshake with the local client
						if err = tlsConn.Handshake(); err != nil {
							handleError(opt, session, err)
							break readLoop // close connection
						}

						c = tlsConn
						goto startOver // hijack and decrypt tls connection
					}

					// maybe it's the others encrypted connection
					in <- inbound.NewHTTPS(session.request, mrc)
				}

				// maybe it's a http connection
				goto readLoop
			}

			prepareRequest(c, session.request)

			// hijack api
			if session.request.URL.Host == opt.ApiHost {
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
				session.response = session.NewErrorResponse(errors.New("invalid URL"))
			} else {
				client = newClientBySourceAndUserAgentIfNil(client, session.request, source, in)

				// send the request to remote server
				session.response, err = client.Do(session.request)

				if err != nil {
					handleError(opt, session, err)
					session.response = session.NewErrorResponse(err)
					if errors.Is(err, ErrCertUnsupported) || strings.Contains(err.Error(), "x509: ") {
						// TODO block unsupported host?
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
			body := res.Body
			defer func(body io.ReadCloser) {
				_ = body.Close()
			}(body)

			session.response = res
		}
	}

	return writeResponse(session, true)
}

func writeResponse(session *Session, keepAlive bool) error {
	H.RemoveHopByHopHeaders(session.response.Header)

	if keepAlive {
		session.response.Header.Set("Connection", "keep-alive")
		session.response.Header.Set("Keep-Alive", "timeout=25")
	}

	// session.response.Close = !keepAlive  // let handler do it

	return session.response.Write(session.conn)
}

func handleApiRequest(session *Session, opt *Option) error {
	if opt.CertConfig != nil && strings.ToLower(session.request.URL.Path) == "/cert.crt" {
		b := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: opt.CertConfig.GetCA().Raw,
		})

		session.response = session.NewResponse(http.StatusOK, bytes.NewReader(b))

		defer func(body io.ReadCloser) {
			_ = body.Close()
		}(session.response.Body)

		session.response.Close = true
		session.response.Header.Set("Content-Type", "application/x-x509-ca-cert")
		session.response.ContentLength = int64(len(b))

		return session.response.Write(session.conn)
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

	defer func(body io.ReadCloser) {
		_ = body.Close()
	}(session.response.Body)

	session.response.Close = true
	session.response.Header.Set("Content-Type", "text/html;charset=utf-8")
	session.response.ContentLength = int64(len(b))

	return session.response.Write(session.conn)
}

func handleError(opt *Option, session *Session, err error) {
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

	H.RemoveHopByHopHeaders(request.Header)
	H.RemoveExtraHTTPHostPort(request)
}

func couldBeWithManInTheMiddleAttack(hostname string, opt *Option) bool {
	if opt.CertConfig == nil {
		return false
	}

	if _, port, err := net.SplitHostPort(hostname); err == nil && (port == "443" || port == "8443") {
		return true
	}

	return false
}

func parseSourceAddress(req *http.Request, c net.Conn, source net.Addr) net.Addr {
	if source != nil {
		return source
	}

	sourceAddress := req.Header.Get("Origin-Request-Source-Address")
	if sourceAddress == "" {
		return c.RemoteAddr()
	}

	req.Header.Del("Origin-Request-Source-Address")

	host, port, err := net.SplitHostPort(sourceAddress)
	if err != nil {
		return c.RemoteAddr()
	}

	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return c.RemoteAddr()
	}

	if ip := net.ParseIP(host); ip != nil {
		return &net.TCPAddr{
			IP:   ip,
			Port: int(p),
		}
	}

	return c.RemoteAddr()
}

func newClientBySourceAndUserAgentIfNil(cli *http.Client, req *http.Request, source net.Addr, in chan<- C.ConnContext) *http.Client {
	if cli != nil {
		return cli
	}

	return newClient(source, req.Header.Get("User-Agent"), in)
}
