package tunnel

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Dreamacro/clash/adapter/inbound"
	N "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"
)

func handleHTTP(ctx *context.HTTPContext, outbound net.Conn) {
	req := ctx.Request()
	conn := ctx.Conn()

	// make outbound close after inbound error or close
	conn = &connLinker{conn, outbound}

	inboundReader := bufio.NewReader(conn)
	outboundReader := bufio.NewReader(outbound)

	inbound.RemoveExtraHTTPHostPort(req)
	host := req.Host
	for {
		keepAlive := strings.TrimSpace(strings.ToLower(req.Header.Get("Proxy-Connection"))) == "keep-alive"

		req.RequestURI = ""
		inbound.RemoveHopByHopHeaders(req.Header)
		err := req.Write(outbound)
		if err != nil {
			break
		}

	handleResponse:
		// resp will be closed after we call resp.Write()
		// see https://golang.org/pkg/net/http/#Response.Write
		resp, err := http.ReadResponse(outboundReader, req)
		if err != nil {
			break
		}
		inbound.RemoveHopByHopHeaders(resp.Header)

		if resp.StatusCode == http.StatusContinue {
			err = resp.Write(conn)
			if err != nil {
				break
			}
			goto handleResponse
		}

		// close conn when header `Connection` is `close`
		if resp.Header.Get("Connection") == "close" {
			keepAlive = false
		}

		if keepAlive {
			resp.Header.Set("Proxy-Connection", "keep-alive")
			resp.Header.Set("Connection", "keep-alive")
			resp.Header.Set("Keep-Alive", "timeout=4")
			resp.Close = false
		} else {
			resp.Close = true
		}
		err = resp.Write(conn)
		if err != nil || resp.Close {
			break
		}

		req, err = http.ReadRequest(inboundReader)
		if err != nil {
			break
		}

		inbound.RemoveExtraHTTPHostPort(req)
		// Sometimes firefox just open a socket to process multiple domains in HTTP
		// The temporary solution is close connection when encountering different HOST
		if req.Host != host {
			break
		}
	}
}

func handleUDPToRemote(packet C.UDPPacket, pc C.PacketConn, metadata *C.Metadata) error {
	defer packet.Drop()

	// local resolve UDP dns
	if !metadata.Resolved() {
		ip, err := resolver.ResolveIP(metadata.Host)
		if err != nil {
			return err
		}
		metadata.DstIP = ip
	}

	addr := metadata.UDPAddr()
	if addr == nil {
		return errors.New("udp addr invalid")
	}

	if _, err := pc.WriteTo(packet.Data(), addr); err != nil {
		return err
	}
	// reset timeout
	pc.SetReadDeadline(time.Now().Add(udpTimeout))

	return nil
}

func handleUDPToLocal(packet C.UDPPacket, pc net.PacketConn, key string, fAddr net.Addr) {
	buf := pool.Get(pool.RelayBufferSize)
	defer pool.Put(buf)
	defer natTable.Delete(key)
	defer pc.Close()

	for {
		pc.SetReadDeadline(time.Now().Add(udpTimeout))
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}

		if fAddr != nil {
			from = fAddr
		}

		_, err = packet.WriteBack(buf[:n], from)
		if err != nil {
			return
		}
	}
}

func handleSocket(ctx C.ConnContext, outbound net.Conn) {
	relay(ctx.Conn(), outbound)
}

// relay copies between left and right bidirectionally.
func relay(leftConn, rightConn net.Conn) {
	ch := make(chan error)

	go func() {
		buf := pool.Get(pool.RelayBufferSize)
		// Wrapping to avoid using *net.TCPConn.(ReadFrom)
		// See also https://github.com/Dreamacro/clash/pull/1209
		_, err := io.CopyBuffer(N.WriteOnlyWriter{Writer: leftConn}, N.ReadOnlyReader{Reader: rightConn}, buf)
		pool.Put(buf)
		leftConn.SetReadDeadline(time.Now())
		ch <- err
	}()

	buf := pool.Get(pool.RelayBufferSize)
	io.CopyBuffer(N.WriteOnlyWriter{Writer: rightConn}, N.ReadOnlyReader{Reader: leftConn}, buf)
	pool.Put(buf)
	rightConn.SetReadDeadline(time.Now())
	<-ch
}

// connLinker make the two net.Conn correlated, for temporary resolution of leaks.
// There is no better way to do this for now.
type connLinker struct {
	net.Conn
	linker net.Conn
}

func (conn *connLinker) Read(b []byte) (n int, err error) {
	n, err = conn.Conn.Read(b)
	if err != nil {
		conn.linker.Close()
	}
	return n, err
}

func (conn *connLinker) Write(b []byte) (n int, err error) {
	n, err = conn.Conn.Write(b)
	if err != nil {
		conn.linker.Close()
	}
	return n, err
}

func (conn *connLinker) Close() error {
	conn.linker.Close()
	return conn.Conn.Close()
}
