//go:build with_gvisor && !no_tailscale && tailscale_host_forward_e2e

package outbound_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	mlog "github.com/metacubex/mihomo/log"
	"github.com/metacubex/tailscale/net/netns"
	"github.com/metacubex/tailscale/net/stun/stuntest"
	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/tstest/integration/testcontrol"
	"github.com/metacubex/tailscale/types/nettype"
	"golang.org/x/crypto/ssh"
)

func TestTailscaleHostForwardE2E(t *testing.T) {
	oldHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(oldHome) })

	controlURL := startControl(t)
	serverHost := "hf-server.tail-scale.ts.net"

	server, err := outbound.NewTailscale(outbound.TailscaleOption{
		Name:       "hf-server",
		Hostname:   "hf-server",
		ControlURL: controlURL,
		StateDir:   filepath.Join("tailscale-e2e", "server"),
		Ephemeral:  true,
		HostForward: outbound.TailscaleHostForwardOption{
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	client, err := outbound.NewTailscale(outbound.TailscaleOption{
		Name:       "hf-client",
		Hostname:   "hf-client",
		ControlURL: controlURL,
		StateDir:   filepath.Join("tailscale-e2e", "client"),
		Ephemeral:  true,
		UDP:        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	var hostForwardWarnings atomic.Int32
	sub := mlog.Subscribe()
	doneLogs := make(chan struct{})
	go func() {
		defer close(doneLogs)
		for ev := range sub {
			if ev.LogLevel >= mlog.WARNING && strings.Contains(ev.Payload, "host-forward") {
				hostForwardWarnings.Add(1)
				t.Logf("host-forward warning: %s", ev.Payload)
			}
		}
	}()
	t.Cleanup(func() {
		mlog.UnSubscribe(sub)
		<-doneLogs
	})

	httpPort := startHTTPService(t)
	httpForward := startTCPForwarder(t, client, serverHost, httpPort, 0)
	eventually(t, 75*time.Second, 2*time.Second, func() error {
		out, err := runCommand(15*time.Second, "curl", "-fsS", "http://"+httpForward)
		if err != nil {
			return fmt.Errorf("curl failed: %w: %s", err, out)
		}
		if !strings.Contains(out, "mihomo-host-forward-ok") {
			return fmt.Errorf("unexpected HTTP response %q", out)
		}
		return nil
	})
	t.Log("HTTP over host-forward succeeded")

	sshdPort := startSSHD(t)
	sshForward := startTCPForwarder(t, client, serverHost, sshdPort, 0)
	eventually(t, 45*time.Second, time.Second, func() error {
		return checkSSHHandshake(sshForward)
	})
	t.Log("SSH handshake over host-forward reached authentication")

	iperfTCPPort := startIperfServer(t)
	iperfTCPForward := startTCPForwarder(t, client, serverHost, iperfTCPPort, 0)
	out, err := runCommand(25*time.Second, "iperf3", "-c", "127.0.0.1", "-p", portString(iperfTCPForward), "-t", "1", "-J")
	if err != nil {
		t.Fatalf("iperf3 TCP failed: %v: %s", err, out)
	}
	t.Log("iperf3 TCP over host-forward succeeded")

	iperfUDPPort := startIperfServer(t)
	iperfUDPForward := startTCPForwarder(t, client, serverHost, iperfUDPPort, 0)
	startUDPForwarder(t, client, serverHost, iperfUDPPort, portNumber(iperfUDPForward))
	out, err = runCommand(30*time.Second, "iperf3", "-u", "-c", "127.0.0.1", "-p", portString(iperfUDPForward), "-t", "1", "-b", "256K", "-J")
	if err != nil {
		t.Fatalf("iperf3 UDP failed: %v: %s", err, out)
	}
	t.Log("iperf3 UDP over host-forward succeeded")

	closedTargetPort := freeTCPPort(t)
	closedForward := startTCPForwarder(t, client, serverHost, closedTargetPort, 0)
	beforeWarnings := hostForwardWarnings.Load()
	if err := checkClosedPort(closedForward); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if got := hostForwardWarnings.Load(); got != beforeWarnings {
		t.Fatalf("closed-port check emitted %d host-forward warnings", got-beforeWarnings)
	}
	t.Log("closed TCP port failed cleanly without host-forward warnings")
}

func startControl(t *testing.T) string {
	t.Helper()
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })

	derpMap := runLocalSTUNDERPMap(t, "127.0.0.1")
	control := &testcontrol.Server{
		DERPMap: derpMap,
		DNSConfig: &tailcfg.DNSConfig{
			Proxied: true,
		},
		MagicDNSDomain: "tail-scale.ts.net",
		Logf:           t.Logf,
		AllOnline:      true,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	return control.HTTPTestServer.URL
}

func runLocalSTUNDERPMap(t *testing.T, ipAddress string) *tailcfg.DERPMap {
	t.Helper()

	stunAddr, stunCleanup := stuntest.ServeWithPacketListener(t, nettype.Std{})
	t.Cleanup(func() {
		stunCleanup()
	})

	// These local nodes can connect directly once STUN publishes endpoints.
	return &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:             "t1",
						RegionID:         1,
						HostName:         ipAddress,
						IPv4:             ipAddress,
						IPv6:             "none",
						STUNPort:         stunAddr.Port,
						DERPPort:         9,
						InsecureForTests: true,
						STUNTestIP:       ipAddress,
					},
				},
			},
		},
	}
}

func startHTTPService(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "mihomo-host-forward-ok\n")
	})}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			t.Errorf("HTTP service failed: %v", err)
		}
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return ln.Addr().(*net.TCPAddr).Port
}

func startSSHD(t *testing.T) int {
	t.Helper()
	if err := os.MkdirAll("/run/sshd", 0o755); err != nil {
		t.Fatal(err)
	}
	port := freeTCPPort(t)
	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, "/usr/sbin/sshd",
		"-D",
		"-e",
		"-p", strconv.Itoa(port),
		"-o", "ListenAddress=127.0.0.1",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "ChallengeResponseAuthentication=no",
		"-o", "PermitRootLogin=yes",
		"-o", "UsePAM=no",
		"-o", "LogLevel=ERROR",
	)
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})
	waitTCPPortInUse(t, port, 5*time.Second, &out)
	return port
}

func startIperfServer(t *testing.T) int {
	t.Helper()
	port := freeTCPPort(t)
	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, "iperf3", "-s", "-1", "-B", "127.0.0.1", "-p", strconv.Itoa(port))
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})
	waitTCPPortInUse(t, port, 5*time.Second, &out)
	return port
}

func startTCPForwarder(t *testing.T, proxy *outbound.Tailscale, host string, targetPort, listenPort int) string {
	t.Helper()
	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", listenPort))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() == nil {
					t.Logf("TCP forward accept failed: %v", err)
				}
				return
			}
			go func() {
				dialCtx, dialCancel := context.WithTimeout(ctx, 45*time.Second)
				remote, err := proxy.DialContext(dialCtx, targetMetadata(C.TCP, host, targetPort))
				dialCancel()
				if err != nil {
					_ = conn.Close()
					t.Logf("TCP forward dial %s:%d failed: %v", host, targetPort, err)
					return
				}
				relayTCP(conn, remote)
			}()
		}
	}()
	return ln.Addr().String()
}

func startUDPForwarder(t *testing.T, proxy *outbound.Tailscale, host string, targetPort, listenPort int) string {
	t.Helper()
	local, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", listenPort))
	if err != nil {
		t.Fatal(err)
	}
	md := targetMetadata(C.UDP, host, targetPort)
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 45*time.Second)
	remote, err := proxy.ListenPacketContext(dialCtx, md)
	dialCancel()
	if err != nil {
		_ = local.Close()
		t.Fatal(err)
	}
	if !md.DstIP.IsValid() {
		_ = local.Close()
		_ = remote.Close()
		t.Fatalf("resolved UDP target %s:%d has no IP", host, targetPort)
	}
	target := net.UDPAddrFromAddrPort(netip.AddrPortFrom(md.DstIP, uint16(targetPort)))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = local.Close()
		_ = remote.Close()
	})

	var peerMu sync.RWMutex
	var localPeer net.Addr
	go func() {
		buffer := make([]byte, 64*1024)
		for {
			n, peer, err := local.ReadFrom(buffer)
			if err != nil {
				if ctx.Err() == nil {
					t.Logf("UDP local read failed: %v", err)
				}
				return
			}
			peerMu.Lock()
			localPeer = peer
			peerMu.Unlock()
			if _, err := remote.WriteTo(buffer[:n], target); err != nil {
				t.Logf("UDP remote write failed: %v", err)
				return
			}
		}
	}()
	go func() {
		buffer := make([]byte, 64*1024)
		for {
			n, _, err := remote.ReadFrom(buffer)
			if err != nil {
				if ctx.Err() == nil {
					t.Logf("UDP remote read failed: %v", err)
				}
				return
			}
			peerMu.RLock()
			peer := localPeer
			peerMu.RUnlock()
			if peer == nil {
				continue
			}
			if _, err := local.WriteTo(buffer[:n], peer); err != nil {
				t.Logf("UDP local write failed: %v", err)
				return
			}
		}
	}()
	return local.LocalAddr().String()
}

func targetMetadata(network C.NetWork, host string, port int) *C.Metadata {
	return &C.Metadata{
		NetWork: network,
		Type:    C.INNER,
		Host:    host,
		DstPort: uint16(port),
	}
}

func relayTCP(left, right net.Conn) {
	defer left.Close()
	defer right.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyAndCloseWrite(left, right)
	}()
	go func() {
		defer wg.Done()
		copyAndCloseWrite(right, left)
	}()
	wg.Wait()
}

func copyAndCloseWrite(dst, src net.Conn) {
	if _, err := io.Copy(dst, src); err == nil {
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
			return
		}
	}
	_ = dst.Close()
}

func checkSSHHandshake(addr string) error {
	conn, err := net.DialTimeout("tcp4", addr, 15*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, _, _, err = ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password("not-a-real-password")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	})
	if err == nil {
		return fmt.Errorf("unexpected SSH authentication success")
	}
	if !strings.Contains(err.Error(), "unable to authenticate") {
		return err
	}
	return nil
}

func checkClosedPort(addr string) error {
	conn, err := net.DialTimeout("tcp4", addr, 10*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("closed-port-probe")); err != nil {
		return nil
	}
	var one [1]byte
	if _, err := conn.Read(one[:]); err != nil {
		return nil
	}
	return fmt.Errorf("closed port unexpectedly accepted data")
}

func eventually(t *testing.T, timeout, interval time.Duration, fn func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := fn(); err != nil {
			lastErr = err
			time.Sleep(interval)
			continue
		}
		return
	}
	t.Fatalf("condition not met within %s: %v", timeout, lastErr)
}

func runCommand(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return out.String(), err
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitTCPPortInUse(t *testing.T, port int, timeout time.Duration, output *bytes.Buffer) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ln, err := net.Listen("tcp4", addr)
		if err != nil {
			return
		}
		_ = ln.Close()
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("port %d was not opened: %s", port, output.String())
}

func portString(addr string) string {
	return strconv.Itoa(portNumber(addr))
}

func portNumber(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		panic(err)
	}
	return n
}
