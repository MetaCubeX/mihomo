//go:build integration

package muxcool_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/socks5"
)

const processE2EUUID = "9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68"

func TestMuxCoolProcessMaxCarriers(t *testing.T) {
	const (
		maxCarriers    = 2
		maxConcurrency = 8
		sessionCount   = maxCarriers * maxConcurrency
		overflowCount  = 4
	)

	binary := buildMihomoProcessE2E(t)
	echoAddress, echoAccepts := startProcessE2EEcho(t)
	serverPort := reserveProcessE2EPort(t)
	relay := startProcessE2ERelay(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)))
	clientPort := reserveProcessE2EPort(t)

	tempDir := t.TempDir()
	serverConfig := filepath.Join(tempDir, "server.yaml")
	clientConfig := filepath.Join(tempDir, "client.yaml")
	writeProcessE2EFile(t, serverConfig, fmt.Sprintf(`
mode: rule
log-level: debug
listeners:
  - name: vless-in
    type: vless
    listen: 127.0.0.1
    port: %d
    allow-insecure: true
    users:
      - username: process-e2e
        uuid: %s
rules:
  - MATCH,DIRECT
`, serverPort, processE2EUUID))
	writeProcessE2EFile(t, clientConfig, fmt.Sprintf(`
mixed-port: %d
allow-lan: false
mode: rule
log-level: debug
proxies:
  - name: vless-mux-cool
    type: vless
    server: 127.0.0.1
    port: %d
    uuid: %s
    network: tcp
    udp: true
    mux.cool:
      enabled: true
      max-concurrency: %d
      max-connections: 128
      max-carriers: %d
rules:
  - MATCH,vless-mux-cool
`, clientPort, relay.port(), processE2EUUID, maxConcurrency, maxCarriers))

	server := startMihomoProcessE2E(t, binary, serverConfig, filepath.Join(tempDir, "server-home"))
	waitProcessE2ETCP(t, server, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)))
	client := startMihomoProcessE2E(t, binary, clientConfig, filepath.Join(tempDir, "client-home"))
	clientAddress := net.JoinHostPort("127.0.0.1", fmt.Sprint(clientPort))
	waitProcessE2ETCP(t, client, clientAddress)

	connections := openProcessE2EWave(t, clientAddress, echoAddress, 0, sessionCount)
	t.Cleanup(func() { closeProcessE2EConnections(connections) })
	if got := relay.total.Load(); got != maxCarriers {
		t.Fatalf("physical carrier connections at capacity = %d, want %d", got, maxCarriers)
	}
	if got := relay.maxActive.Load(); got != maxCarriers {
		t.Fatalf("peak active carrier connections = %d, want %d", got, maxCarriers)
	}

	overflowResults := startProcessE2EWave(clientAddress, echoAddress, 1, overflowCount)
	select {
	case result := <-overflowResults:
		if result.connection != nil {
			_ = result.connection.Close()
		}
		t.Fatalf("overflow session completed before carrier capacity was released: %v", result.err)
	case <-time.After(250 * time.Millisecond):
	}
	if got := relay.total.Load(); got != maxCarriers {
		t.Fatalf("physical carrier connections while capped = %d, want %d", got, maxCarriers)
	}

	closeProcessE2EConnections(connections[:overflowCount])
	connections = connections[overflowCount:]
	connections = append(connections, collectProcessE2EConnections(t, overflowResults, overflowCount)...)
	if got := relay.total.Load(); got != maxCarriers {
		t.Fatalf("physical carrier connections after capacity reuse = %d, want %d", got, maxCarriers)
	}
	closeProcessE2EConnections(connections)
	connections = nil

	connections = openProcessE2EWave(t, clientAddress, echoAddress, 2, sessionCount)
	closeProcessE2EConnections(connections)
	connections = nil

	wantLogical := 2*sessionCount + overflowCount
	if got := echoAccepts.Load(); got != int32(wantLogical) {
		t.Fatalf("logical target connections = %d, want %d", got, wantLogical)
	}
	if got := relay.total.Load(); got != maxCarriers {
		t.Fatalf("physical carrier connections after reuse = %d, want %d", got, maxCarriers)
	}
	t.Logf(
		"logical sessions=%d physical carriers=%d peak active carriers=%d",
		echoAccepts.Load(), relay.total.Load(), relay.maxActive.Load(),
	)
}

func openProcessE2EWave(t *testing.T, clientAddress, targetAddress string, wave, count int) []net.Conn {
	t.Helper()
	return collectProcessE2EConnections(t, startProcessE2EWave(clientAddress, targetAddress, wave, count), count)
}

type processE2EResult struct {
	connection net.Conn
	err        error
}

func startProcessE2EWave(clientAddress, targetAddress string, wave, count int) <-chan processE2EResult {
	results := make(chan processE2EResult, count)
	start := make(chan struct{})
	for index := 0; index < count; index++ {
		go func(index int) {
			<-start
			connection, err := net.DialTimeout("tcp", clientAddress, 5*time.Second)
			if err != nil {
				results <- processE2EResult{err: fmt.Errorf("dial mixed listener: %w", err)}
				return
			}
			if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				_ = connection.Close()
				results <- processE2EResult{err: err}
				return
			}
			if _, err := socks5.ClientHandshake(connection, socks5.ParseAddr(targetAddress), socks5.CmdConnect, nil); err != nil {
				_ = connection.Close()
				results <- processE2EResult{err: fmt.Errorf("SOCKS5 handshake: %w", err)}
				return
			}
			payload := []byte(fmt.Sprintf("wave-%d-session-%d", wave, index))
			if _, err := connection.Write(payload); err != nil {
				_ = connection.Close()
				results <- processE2EResult{err: fmt.Errorf("write payload: %w", err)}
				return
			}
			response := make([]byte, len(payload))
			if _, err := io.ReadFull(connection, response); err != nil {
				_ = connection.Close()
				results <- processE2EResult{err: fmt.Errorf("read payload: %w", err)}
				return
			}
			if !bytes.Equal(response, payload) {
				_ = connection.Close()
				results <- processE2EResult{err: fmt.Errorf("response = %q, want %q", response, payload)}
				return
			}
			_ = connection.SetDeadline(time.Time{})
			results <- processE2EResult{connection: connection}
		}(index)
	}
	close(start)
	return results
}

func collectProcessE2EConnections(t *testing.T, results <-chan processE2EResult, count int) []net.Conn {
	t.Helper()
	connections := make([]net.Conn, 0, count)
	for index := 0; index < count; index++ {
		current := <-results
		if current.err != nil {
			closeProcessE2EConnections(connections)
			t.Fatal(current.err)
		}
		connections = append(connections, current.connection)
	}
	return connections
}

func closeProcessE2EConnections(connections []net.Conn) {
	for _, connection := range connections {
		_ = connection.Close()
	}
}

type processE2ERelay struct {
	listener  net.Listener
	backend   string
	total     atomic.Int32
	active    atomic.Int32
	maxActive atomic.Int32
}

func startProcessE2ERelay(t *testing.T, backend string) *processE2ERelay {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay := &processE2ERelay{listener: listener, backend: backend}
	t.Cleanup(func() { _ = listener.Close() })
	go relay.acceptLoop()
	return relay
}

func (r *processE2ERelay) port() int {
	return r.listener.Addr().(*net.TCPAddr).Port
}

func (r *processE2ERelay) acceptLoop() {
	for {
		client, err := r.listener.Accept()
		if err != nil {
			return
		}
		r.total.Add(1)
		active := r.active.Add(1)
		for {
			peak := r.maxActive.Load()
			if active <= peak || r.maxActive.CompareAndSwap(peak, active) {
				break
			}
		}
		go r.forward(client)
	}
}

func (r *processE2ERelay) forward(client net.Conn) {
	defer r.active.Add(-1)
	backend, err := net.DialTimeout("tcp", r.backend, 5*time.Second)
	if err != nil {
		_ = client.Close()
		return
	}

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(backend, client)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, backend)
		done <- struct{}{}
	}()
	<-done
	_ = client.Close()
	_ = backend.Close()
	<-done
}

func startProcessE2EEcho(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepts atomic.Int32
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	return listener.Addr().String(), &accepts
}

type lockedProcessE2EBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *lockedProcessE2EBuffer) Write(payload []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(payload)
}

func (b *lockedProcessE2EBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

type mihomoProcessE2E struct {
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	err    error
	output lockedProcessE2EBuffer
}

func startMihomoProcessE2E(t *testing.T, binary, config, home string) *mihomoProcessE2E {
	t.Helper()
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	process := &mihomoProcessE2E{cancel: cancel, done: make(chan struct{})}
	command := exec.CommandContext(ctx, binary, "-d", home, "-f", config)
	command.Stdout = &process.output
	command.Stderr = &process.output
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	go func() {
		err := command.Wait()
		process.mu.Lock()
		process.err = err
		process.mu.Unlock()
		close(process.done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-process.done:
		case <-time.After(5 * time.Second):
			t.Errorf("mihomo process did not stop\n%s", process.output.String())
		}
		if t.Failed() {
			t.Log(process.output.String())
		}
	})
	return process
}

func (p *mihomoProcessE2E) waitError() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func waitProcessE2ETCP(t *testing.T, process *mihomoProcessE2E, address string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
		if err == nil {
			_ = connection.Close()
			return
		}
		select {
		case <-process.done:
			t.Fatalf("mihomo exited before listening on %s: %v\n%s", address, process.waitError(), process.output.String())
		case <-ctx.Done():
			t.Fatalf("mihomo did not listen on %s: %v\n%s", address, context.Cause(ctx), process.output.String())
		case <-ticker.C:
		}
	}
}

func buildMihomoProcessE2E(t *testing.T) string {
	t.Helper()
	if binary := os.Getenv("MIHOMO_E2E_BINARY"); binary != "" {
		return binary
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "mihomo")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	command := exec.Command("go", "build", "-trimpath", "-o", binary, ".")
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build mihomo: %v\n%s", err, output)
	}
	return binary
}

func reserveProcessE2EPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func writeProcessE2EFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
