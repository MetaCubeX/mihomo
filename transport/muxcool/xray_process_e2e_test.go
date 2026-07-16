//go:build integration

package muxcool_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/miekg/dns"
)

func TestMuxCoolProcessXrayCompatibility(t *testing.T) {
	mihomoBinary := buildMihomoProcessE2E(t)
	xrayBinary := buildXrayProcessE2E(t)

	t.Run("mihomo-client/xray-server/tcp", func(t *testing.T) {
		tcpAddress, _ := startProcessE2EEcho(t)
		serverPort := reserveProcessE2EPort(t)
		clientPort := reserveProcessE2EPort(t)
		tempDir := t.TempDir()

		serverConfig := filepath.Join(tempDir, "xray-server.json")
		clientConfig := filepath.Join(tempDir, "mihomo-client.yaml")
		writeProcessE2EFile(t, serverConfig, xrayServerProcessE2EConfig(serverPort))
		writeProcessE2EFile(t, clientConfig, mihomoClientProcessE2EConfig(clientPort, serverPort, 0))

		server := startXrayProcessE2E(t, xrayBinary, serverConfig, nil)
		waitProcessE2ETCP(t, server, fmt.Sprintf("127.0.0.1:%d", serverPort))
		client := startMihomoProcessE2E(t, mihomoBinary, clientConfig, filepath.Join(tempDir, "mihomo-home"))
		clientAddress := fmt.Sprintf("127.0.0.1:%d", clientPort)
		waitProcessE2ETCP(t, client, clientAddress)

		processE2ETCPRoundTrip(t, clientAddress, tcpAddress)
	})

	t.Run("xray-client/mihomo-server/tcp", func(t *testing.T) {
		tcpAddress, _ := startProcessE2EEcho(t)
		serverPort := reserveProcessE2EPort(t)
		clientPort := reserveProcessE2EPort(t)
		tempDir := t.TempDir()

		serverConfig := filepath.Join(tempDir, "mihomo-server.yaml")
		clientConfig := filepath.Join(tempDir, "xray-client.json")
		writeProcessE2EFile(t, serverConfig, mihomoServerProcessE2EConfig(serverPort))
		writeProcessE2EFile(t, clientConfig, xrayClientProcessE2EConfig(clientPort, serverPort, 0))

		server := startMihomoProcessE2E(t, mihomoBinary, serverConfig, filepath.Join(tempDir, "mihomo-home"))
		waitProcessE2ETCP(t, server, fmt.Sprintf("127.0.0.1:%d", serverPort))
		client := startXrayProcessE2E(t, xrayBinary, clientConfig, []string{"XRAY_CONE_DISABLED=false"})
		clientAddress := fmt.Sprintf("127.0.0.1:%d", clientPort)
		waitProcessE2ETCP(t, client, clientAddress)

		processE2ETCPRoundTrip(t, clientAddress, tcpAddress)
	})

	t.Run("mihomo-client/xray-server/udp", func(t *testing.T) {
		dnsTarget := startProcessE2EDNSServer(t)
		serverPort := reserveProcessE2EPort(t)
		clientPort := reserveProcessE2EPort(t)
		dnsPort := reserveProcessE2EPort(t)
		tempDir := t.TempDir()

		serverConfig := filepath.Join(tempDir, "xray-server.json")
		clientConfig := filepath.Join(tempDir, "mihomo-client.yaml")
		writeProcessE2EFile(t, serverConfig, xrayServerProcessE2EConfig(serverPort))
		writeProcessE2EFile(t, clientConfig, mihomoDNSClientProcessE2EConfig(clientPort, dnsPort, serverPort, dnsTarget))

		server := startXrayProcessE2E(t, xrayBinary, serverConfig, nil)
		waitProcessE2ETCP(t, server, fmt.Sprintf("127.0.0.1:%d", serverPort))
		client := startMihomoProcessE2E(t, mihomoBinary, clientConfig, filepath.Join(tempDir, "mihomo-home"))
		waitProcessE2ETCP(t, client, fmt.Sprintf("127.0.0.1:%d", clientPort))

		processE2EDNSRoundTrip(t, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	})

	t.Run("mihomo-client/xray-server/xudp", func(t *testing.T) {
		udpAddress := startProcessE2EUDPEcho(t)
		serverPort := reserveProcessE2EPort(t)
		clientPort := reserveProcessE2EPort(t)
		tempDir := t.TempDir()

		serverConfig := filepath.Join(tempDir, "xray-server.json")
		clientConfig := filepath.Join(tempDir, "mihomo-client.yaml")
		writeProcessE2EFile(t, serverConfig, xrayServerProcessE2EConfig(serverPort))
		writeProcessE2EFile(t, clientConfig, mihomoClientProcessE2EConfig(clientPort, serverPort, 4))

		server := startXrayProcessE2E(t, xrayBinary, serverConfig, nil)
		waitProcessE2ETCP(t, server, fmt.Sprintf("127.0.0.1:%d", serverPort))
		client := startMihomoProcessE2E(t, mihomoBinary, clientConfig, filepath.Join(tempDir, "mihomo-home"))
		clientAddress := fmt.Sprintf("127.0.0.1:%d", clientPort)
		waitProcessE2ETCP(t, client, clientAddress)

		processE2ESOCKSUDPRoundTrip(t, clientAddress, udpAddress)
	})

	t.Run("xray-client/mihomo-server/udp", func(t *testing.T) {
		udpAddress := startProcessE2EUDPEcho(t)
		serverPort := reserveProcessE2EPort(t)
		clientPort := reserveProcessE2EPort(t)
		tempDir := t.TempDir()

		serverConfig := filepath.Join(tempDir, "mihomo-server.yaml")
		clientConfig := filepath.Join(tempDir, "xray-client.json")
		writeProcessE2EFile(t, serverConfig, mihomoServerProcessE2EConfig(serverPort))
		writeProcessE2EFile(t, clientConfig, xrayClientProcessE2EConfig(clientPort, serverPort, 0))

		server := startMihomoProcessE2E(t, mihomoBinary, serverConfig, filepath.Join(tempDir, "mihomo-home"))
		waitProcessE2ETCP(t, server, fmt.Sprintf("127.0.0.1:%d", serverPort))
		client := startXrayProcessE2E(t, xrayBinary, clientConfig, []string{"XRAY_CONE_DISABLED=true"})
		clientAddress := fmt.Sprintf("127.0.0.1:%d", clientPort)
		waitProcessE2ETCP(t, client, clientAddress)

		processE2ESOCKSUDPRoundTrip(t, clientAddress, udpAddress)
	})

	t.Run("xray-client/mihomo-server/xudp", func(t *testing.T) {
		udpAddress := startProcessE2EUDPEcho(t)
		serverPort := reserveProcessE2EPort(t)
		clientPort := reserveProcessE2EPort(t)
		tempDir := t.TempDir()

		serverConfig := filepath.Join(tempDir, "mihomo-server.yaml")
		clientConfig := filepath.Join(tempDir, "xray-client.json")
		writeProcessE2EFile(t, serverConfig, mihomoServerProcessE2EConfig(serverPort))
		writeProcessE2EFile(t, clientConfig, xrayClientProcessE2EConfig(clientPort, serverPort, 4))

		server := startMihomoProcessE2E(t, mihomoBinary, serverConfig, filepath.Join(tempDir, "mihomo-home"))
		waitProcessE2ETCP(t, server, fmt.Sprintf("127.0.0.1:%d", serverPort))
		client := startXrayProcessE2E(t, xrayBinary, clientConfig, []string{"XRAY_CONE_DISABLED=false"})
		clientAddress := fmt.Sprintf("127.0.0.1:%d", clientPort)
		waitProcessE2ETCP(t, client, clientAddress)

		processE2ESOCKSUDPRoundTrip(t, clientAddress, udpAddress)
	})
}

func processE2ETCPRoundTrip(t *testing.T, clientAddress, targetAddress string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var lastError error
	for time.Now().Before(deadline) {
		result := <-startProcessE2EWave(clientAddress, targetAddress, 0, 1)
		if result.err == nil {
			_ = result.connection.Close()
			return
		}
		lastError = result.err
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("TCP round trip did not become ready: %v", lastError)
}

func xrayServerProcessE2EConfig(port int) string {
	return fmt.Sprintf(`{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "tag": "vless-in",
    "listen": "127.0.0.1",
    "port": %d,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": %q}],
      "decryption": "none"
    }
  }],
  "outbounds": [{
    "tag": "direct",
    "protocol": "freedom",
    "settings": {"finalRules": [{"action": "allow", "network": "tcp,udp"}]}
  }]
}`, port, processE2EUUID)
}

func xrayClientProcessE2EConfig(socksPort, serverPort, xudpConcurrency int) string {
	return fmt.Sprintf(`{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "tag": "socks-in",
    "listen": "127.0.0.1",
    "port": %d,
    "protocol": "socks",
    "settings": {"auth": "noauth", "udp": true}
  }],
  "outbounds": [{
    "tag": "vless-mux-cool",
    "protocol": "vless",
    "settings": {"vnext": [{
      "address": "127.0.0.1",
      "port": %d,
      "users": [{"id": %q, "encryption": "none"}]
    }]},
    "mux": {
      "enabled": true,
      "concurrency": 8,
      "xudpConcurrency": %d,
      "xudpProxyUDP443": "allow"
    }
  }]
}`, socksPort, serverPort, processE2EUUID, xudpConcurrency)
}

func mihomoServerProcessE2EConfig(port int) string {
	return fmt.Sprintf(`
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
`, port, processE2EUUID)
}

func mihomoClientProcessE2EConfig(mixedPort, serverPort, xudpConcurrency int) string {
	return fmt.Sprintf(`
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
      max-concurrency: 8
      max-connections: 128
      max-carriers: 4
      xudp-concurrency: %d
      xudp-proxy-udp443: allow
rules:
  - MATCH,vless-mux-cool
`, mixedPort, serverPort, processE2EUUID, xudpConcurrency)
}

func mihomoDNSClientProcessE2EConfig(mixedPort, dnsPort, serverPort int, dnsTarget string) string {
	return fmt.Sprintf(`
mixed-port: %d
allow-lan: false
mode: rule
log-level: debug
dns:
  enable: true
  listen: 127.0.0.1:%d
  default-nameserver:
    - 127.0.0.1
  nameserver:
    - "udp://%s#vless-mux-cool"
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
      max-concurrency: 8
      max-connections: 128
      max-carriers: 4
      xudp-concurrency: 0
      xudp-proxy-udp443: allow
rules:
  - MATCH,vless-mux-cool
`, mixedPort, dnsPort, dnsTarget, serverPort, processE2EUUID)
}

func startProcessE2EUDPEcho(t *testing.T) string {
	t.Helper()
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	go func() {
		buffer := make([]byte, 64*1024)
		for {
			length, source, err := connection.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = connection.WriteToUDP(buffer[:length], source)
		}
	}()
	return connection.LocalAddr().String()
}

func processE2ESOCKSUDPRoundTrip(t *testing.T, socksAddress, targetAddress string) {
	t.Helper()
	control, err := net.DialTimeout("tcp", socksAddress, 5*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS control connection: %v", err)
	}
	defer control.Close()
	if err := control.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	relay, err := socks5.ClientHandshake(control, socks5.ParseAddr("0.0.0.0:0"), socks5.CmdUDPAssociate, nil)
	if err != nil {
		t.Fatalf("SOCKS5 UDP associate: %v", err)
	}

	packetConnection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer packetConnection.Close()
	relayAddress := relay.UDPAddr()
	if relayAddress == nil {
		t.Fatalf("SOCKS5 UDP relay address %q is not an IP address", relay)
	}
	if relayAddress.IP.IsUnspecified() {
		relayAddress.IP = net.ParseIP("127.0.0.1")
	}

	payload := []byte("mux.cool cross-runtime UDP payload")
	target := socks5.ParseAddr(targetAddress)
	packet, err := socks5.EncodeUDPPacket(target, payload)
	if err != nil {
		t.Fatal(err)
	}
	responseBuffer := make([]byte, 64*1024)
	deadline := time.Now().Add(10 * time.Second)
	var length int
	for {
		if _, err := packetConnection.WriteToUDP(packet, relayAddress); err != nil {
			t.Fatalf("write SOCKS5 UDP packet: %v", err)
		}
		readDeadline := time.Now().Add(500 * time.Millisecond)
		if readDeadline.After(deadline) {
			readDeadline = deadline
		}
		if err := packetConnection.SetReadDeadline(readDeadline); err != nil {
			t.Fatal(err)
		}
		length, _, err = packetConnection.ReadFromUDP(responseBuffer)
		if err == nil {
			break
		}
		if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() || !time.Now().Before(deadline) {
			t.Fatalf("read SOCKS5 UDP packet: %v", err)
		}
	}
	responseTarget, responsePayload, err := socks5.DecodeUDPPacket(responseBuffer[:length])
	if err != nil {
		t.Fatalf("decode SOCKS5 UDP packet: %v", err)
	}
	if responseTarget.String() != target.String() {
		t.Fatalf("SOCKS5 UDP response target = %s, want %s", responseTarget, target)
	}
	if !bytes.Equal(responsePayload, payload) {
		t.Fatalf("SOCKS5 UDP response payload = %q, want %q", responsePayload, payload)
	}
}

func startProcessE2EDNSServer(t *testing.T) string {
	t.Helper()
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{
		PacketConn: connection,
		Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
			response := new(dns.Msg)
			response.SetReply(request)
			response.Authoritative = true
			if len(request.Question) > 0 {
				response.Answer = append(response.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("192.0.2.1"),
				})
			}
			_ = writer.WriteMsg(response)
		}),
	}
	t.Cleanup(func() { _ = server.Shutdown() })
	go func() { _ = server.ActivateAndServe() }()
	return connection.LocalAddr().String()
}

func processE2EDNSRoundTrip(t *testing.T, serverAddress string) {
	t.Helper()
	request := new(dns.Msg)
	request.SetQuestion("mux-cool-process.test.", dns.TypeA)
	response, _, err := (&dns.Client{Net: "udp", Timeout: 10 * time.Second}).Exchange(request, serverAddress)
	if err != nil {
		t.Fatalf("DNS round trip: %v", err)
	}
	if len(response.Answer) != 1 {
		t.Fatalf("DNS answer count = %d, want 1", len(response.Answer))
	}
	answer, ok := response.Answer[0].(*dns.A)
	if !ok || !answer.A.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("DNS answer = %v, want 192.0.2.1", response.Answer[0])
	}
}

func startXrayProcessE2E(t *testing.T, binary, config string, environment []string) *mihomoProcessE2E {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	process := &mihomoProcessE2E{cancel: cancel, done: make(chan struct{})}
	command := exec.CommandContext(ctx, binary, "run", "-config", config)
	command.Env = processE2EEnvironment(environment)
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
			t.Errorf("Xray process did not stop\n%s", process.output.String())
		}
		if t.Failed() {
			t.Log(process.output.String())
		}
	})
	return process
}

func processE2EEnvironment(overrides []string) []string {
	environment := os.Environ()
	for _, override := range overrides {
		key, _, _ := strings.Cut(override, "=")
		prefix := key + "="
		filtered := environment[:0]
		for _, entry := range environment {
			if !strings.HasPrefix(entry, prefix) {
				filtered = append(filtered, entry)
			}
		}
		environment = append(filtered, override)
	}
	return environment
}

func buildXrayProcessE2E(t *testing.T) string {
	t.Helper()
	if binary := os.Getenv("XRAY_E2E_BINARY"); binary != "" {
		return binary
	}

	root := os.Getenv("XRAY_CORE_ROOT")
	if root == "" {
		mihomoRoot, err := filepath.Abs(filepath.Join("..", ".."))
		if err != nil {
			t.Fatal(err)
		}
		root = filepath.Join(filepath.Dir(mihomoRoot), "Xray-core")
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Skipf("Xray-core source is unavailable at %s; set XRAY_CORE_ROOT or XRAY_E2E_BINARY", root)
	}

	binary := filepath.Join(t.TempDir(), "xray")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	command := exec.Command("go", "build", "-trimpath", "-o", binary, "./main")
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build Xray: %v\n%s", err, output)
	}
	return binary
}
