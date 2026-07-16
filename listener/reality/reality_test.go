package reality

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestConfigBuildUsesMillisecondsForMaxTimeDifference(t *testing.T) {
	builder, err := validConfig(func(c *Config) { c.MaxTimeDifference = 1500 }).Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := builder.realityConfig.MaxTimeDiff, 1500*time.Millisecond; got != want {
		t.Fatalf("MaxTimeDiff = %v, want %v", got, want)
	}
}

func TestConfigBuildAppliesXrayVersionPolicy(t *testing.T) {
	tests := []struct {
		name    string
		min     string
		max     string
		wantMin []byte
		wantMax []byte
		wantErr bool
	}{
		{name: "default minimum", wantMin: []byte{26, 3, 27}},
		{name: "explicit bounds", min: "26.7.11", max: "27.0.0", wantMin: []byte{26, 7, 11}, wantMax: []byte{27, 0, 0}},
		{name: "minimum below safety floor", min: "26.3.26", wantErr: true},
		{name: "minimum missing component", min: "26.3", wantErr: true},
		{name: "maximum missing component", max: "26.7", wantErr: true},
		{name: "component overflow", min: "26.300.1", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			builder, err := validConfig(func(c *Config) {
				c.MinClientVersion = test.min
				c.MaxClientVersion = test.max
			}).Build(nil)
			if test.wantErr {
				if err == nil {
					t.Fatal("Build() error = nil")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := builder.realityConfig.MinClientVer; !bytesEqual(got, test.wantMin) {
				t.Fatalf("MinClientVer = %v, want %v", got, test.wantMin)
			}
			if got := builder.realityConfig.MaxClientVer; !bytesEqual(got, test.wantMax) {
				t.Fatalf("MaxClientVer = %v, want %v", got, test.wantMax)
			}
		})
	}
}

func TestConfigBuildInfersXrayTargetTypeAndValidatesXver(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		typeName string
		xver     uint64
		wantType string
		wantDest string
		wantErr  bool
	}{
		{name: "tcp address", target: "example.com:443", wantType: "tcp", wantDest: "example.com:443"},
		{name: "tcp port", target: "443", wantType: "tcp", wantDest: "localhost:443"},
		{name: "explicit tcp", target: "example.com:443", typeName: "tcp", xver: 2, wantType: "tcp", wantDest: "example.com:443"},
		{name: "unix path", target: "/tmp/reality.sock", wantType: "unix", wantDest: "/tmp/reality.sock"},
		{name: "invalid xver", target: "example.com:443", xver: 3, wantErr: true},
		{name: "invalid target", target: "not-an-address", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			builder, err := validConfig(func(c *Config) {
				c.Dest = ""
				c.Target = test.target
				c.Type = test.typeName
				c.Xver = test.xver
			}).Build(nil)
			if test.wantErr {
				if err == nil {
					t.Fatal("Build() error = nil")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := builder.realityConfig.Type; got != test.wantType {
				t.Fatalf("Type = %q, want %q", got, test.wantType)
			}
			if got := builder.realityConfig.Dest; got != test.wantDest {
				t.Fatalf("Dest = %q, want %q", got, test.wantDest)
			}
			if got := builder.realityConfig.Xver; got != byte(test.xver) {
				t.Fatalf("Xver = %d, want %d", got, test.xver)
			}
		})
	}
	_ = runtime.GOOS // unix address normalization has OS-specific follow-up coverage
}

func TestConfigBuildDialsUnixTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets are not available on Windows")
	}
	path := filepath.Join(os.TempDir(), "mihomo-reality-"+strconv.FormatInt(time.Now().UnixNano(), 10)+".sock")
	defer os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	builder, err := validConfig(func(c *Config) {
		c.Dest = ""
		c.Target = path
	}).Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		accepted <- conn
	}()
	client, err := builder.realityConfig.DialContext(context.Background(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	if server == nil {
		t.Fatal("unix target did not accept the REALITY dial")
	}
	defer server.Close()
}

func TestConfigBuildValidatesMldsa65Seed(t *testing.T) {
	privateKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	validSeedBytes := make([]byte, 32)
	validSeedBytes[0] = 1
	validSeed := base64.RawURLEncoding.EncodeToString(validSeedBytes)

	tests := []struct {
		name    string
		seed    string
		wantErr bool
	}{
		{name: "omitted"},
		{name: "valid", seed: validSeed},
		{name: "same as private key", seed: privateKey, wantErr: true},
		{name: "wrong length", seed: base64.RawURLEncoding.EncodeToString(make([]byte, 31)), wantErr: true},
		{name: "invalid base64", seed: "***", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			builder, err := validConfig(func(c *Config) { c.Mldsa65Seed = test.seed }).Build(nil)
			if test.wantErr {
				if err == nil {
					t.Fatal("Build() error = nil")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if test.seed != "" && len(builder.mldsa65Seed) != 32 {
				t.Fatalf("mldsa65 seed length = %d, want 32", len(builder.mldsa65Seed))
			}
		})
	}
}

func TestConfigBuildOpensMasterKeyLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reality.keys")
	builder, err := validConfig(func(c *Config) { c.MasterKeyLog = path }).Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	writer := builder.realityConfig.KeyLogWriter
	if writer == nil {
		t.Fatal("KeyLogWriter = nil")
	}
	if _, err := io.WriteString(writer, "SERVER_HANDSHAKE_TRAFFIC_SECRET test\n"); err != nil {
		t.Fatal(err)
	}
	if closer, ok := writer.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			t.Fatal(err)
		}
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(contents), "SERVER_HANDSHAKE_TRAFFIC_SECRET test\n"; got != want {
		t.Fatalf("key log = %q, want %q", got, want)
	}
}

func validConfig(modify func(*Config)) Config {
	c := Config{
		Dest:        "127.0.0.1:443",
		PrivateKey:  base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		ShortID:     []string{"0123456789abcdef"},
		ServerNames: []string{"example.com"},
	}
	if modify != nil {
		modify(&c)
	}
	return c
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
