package reality

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inner"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"

	utls "github.com/metacubex/utls"
)

type Conn = utls.Conn
type LimitFallback = utls.RealityLimitFallback

type Config struct {
	Target            string
	Dest              string
	Type              string
	Xver              uint64
	PrivateKey        string
	ShortID           []string
	ServerNames       []string
	MinClientVersion  string
	MaxClientVersion  string
	MaxTimeDifference int
	Mldsa65Seed       string
	Show              bool
	MasterKeyLog      string
	Proxy             string

	LimitFallbackUpload   LimitFallback
	LimitFallbackDownload LimitFallback
}

func (c Config) Build(tunnel C.Tunnel) (*Builder, error) {
	realityConfig := &utls.RealityConfig{}
	realityConfig.SessionTicketsDisabled = true
	target := c.Dest
	if c.Target != "" {
		target = c.Target
	}
	typeName, target, err := normalizeTarget(c.Type, target)
	if err != nil {
		return nil, err
	}
	if c.Xver > 2 {
		return nil, fmt.Errorf("invalid PROXY protocol version %d: xver only accepts 0, 1, 2", c.Xver)
	}
	realityConfig.Type = typeName
	realityConfig.Dest = target
	realityConfig.Xver = byte(c.Xver)
	realityConfig.Time = ntp.Now
	realityConfig.ServerNames = make(map[string]bool)
	if len(c.ServerNames) == 0 {
		return nil, errors.New("empty server-names")
	}
	realityConfig.Log = log.Infoln
	if !c.Show {
		realityConfig.Log = nil
	}
	for _, it := range c.ServerNames {
		realityConfig.ServerNames[it] = true
	}
	privateKey, err := base64.RawURLEncoding.DecodeString(c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(privateKey) != 32 {
		return nil, errors.New("invalid private key")
	}
	realityConfig.PrivateKey = privateKey

	realityConfig.MinClientVer, err = parseClientVersion(c.MinClientVersion, []byte{26, 3, 27}, true)
	if err != nil {
		return nil, fmt.Errorf("invalid min-client-ver: %w", err)
	}
	if c.MaxClientVersion != "" {
		realityConfig.MaxClientVer, err = parseClientVersion(c.MaxClientVersion, nil, false)
		if err != nil {
			return nil, fmt.Errorf("invalid max-client-ver: %w", err)
		}
	}

	realityConfig.MaxTimeDiff = time.Duration(c.MaxTimeDifference) * time.Millisecond

	realityConfig.ShortIds = make(map[[8]byte]bool)
	if len(c.ShortID) == 0 {
		return nil, errors.New("empty short-id")
	}
	for i, shortIDString := range c.ShortID {
		var shortID [8]byte
		decodedLen := hex.DecodedLen(len(shortIDString))
		if decodedLen > 8 {
			return nil, fmt.Errorf("invalid short_id[%d]: %s", i, shortIDString)
		}
		decodedLen, err = hex.Decode(shortID[:], []byte(shortIDString))
		if err != nil {
			return nil, fmt.Errorf("decode short_id[%d] '%s': %w", i, shortIDString, err)
		}
		if decodedLen > 8 {
			return nil, fmt.Errorf("invalid short_id[%d]: %s", i, shortIDString)
		}
		realityConfig.ShortIds[shortID] = true
	}

	realityConfig.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network == "unix" {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
		return inner.HandleTcp(tunnel, address, c.Proxy)
	}

	realityConfig.LimitFallbackUpload = c.LimitFallbackUpload
	realityConfig.LimitFallbackDownload = c.LimitFallbackDownload

	var mldsa65Seed []byte
	if c.Mldsa65Seed != "" {
		if c.Mldsa65Seed == c.PrivateKey {
			return nil, errors.New("mldsa65-seed and private-key cannot be the same value")
		}
		mldsa65Seed, err = base64.RawURLEncoding.DecodeString(c.Mldsa65Seed)
		if err != nil || len(mldsa65Seed) != 32 {
			return nil, errors.New("invalid mldsa65-seed")
		}
		realityConfig.Mldsa65Key, _, err = utls.RealityMldsa65KeyFromSeed(mldsa65Seed)
		if err != nil {
			return nil, fmt.Errorf("derive ML-DSA-65 key: %w", err)
		}
	}
	if c.MasterKeyLog != "" && c.MasterKeyLog != "none" {
		realityConfig.KeyLogWriter, err = os.OpenFile(c.MasterKeyLog, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
		if err != nil {
			return nil, fmt.Errorf("open REALITY master key log: %w", err)
		}
	}

	return &Builder{realityConfig: realityConfig, mldsa65Seed: mldsa65Seed}, nil
}

type Builder struct {
	realityConfig *utls.RealityConfig
	mldsa65Seed   []byte
}

func normalizeTarget(typeName, target string) (string, string, error) {
	if target == "" {
		return "", "", errors.New("empty target")
	}
	if typeName == "" {
		switch target[0] {
		case '@', '/':
			typeName = "unix"
			if target[0] == '@' && len(target) > 1 && target[1] == '@' && (runtime.GOOS == "linux" || runtime.GOOS == "android") {
				fullAddress := make([]byte, len(syscall.RawSockaddrUnix{}.Path))
				copy(fullAddress, target[1:])
				target = string(fullAddress)
			}
		default:
			if _, err := strconv.Atoi(target); err == nil {
				target = net.JoinHostPort("localhost", target)
			}
			if _, _, err := net.SplitHostPort(target); err == nil {
				typeName = "tcp"
			}
		}
	}
	if typeName != "tcp" && typeName != "unix" {
		return "", "", fmt.Errorf("invalid target %q with type %q", target, typeName)
	}
	return typeName, target, nil
}

func parseClientVersion(value string, defaultValue []byte, enforceFloor bool) ([]byte, error) {
	if value == "" {
		return append([]byte(nil), defaultValue...), nil
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return nil, errors.New("version must have exactly three components")
	}
	version := make([]byte, 3)
	for i, part := range parts {
		component, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("component %d %q must be between 0 and 255", i, part)
		}
		version[i] = byte(component)
	}
	if enforceFloor && compareVersion(version, []byte{26, 3, 27}) < 0 {
		return nil, errors.New("version must be at least 26.3.27")
	}
	return version, nil
}

func compareVersion(left, right []byte) int {
	for i := 0; i < len(left) && i < len(right); i++ {
		if left[i] < right[i] {
			return -1
		}
		if left[i] > right[i] {
			return 1
		}
	}
	return len(left) - len(right)
}

func (b Builder) NewListener(l net.Listener) net.Listener {
	return N.NewHandleContextListener(context.Background(), l, func(ctx context.Context, conn net.Conn) (net.Conn, error) {
		c, err := utls.RealityServer(ctx, conn, b.realityConfig)
		if err != nil {
			if b.realityConfig.Log != nil {
				b.realityConfig.Log("REALITY server handshake failed: %v", err)
			}
			return nil, err
		}
		// Due to low implementation quality, the reality server intercepted half-close and caused memory leaks.
		// We fixed it by calling Close() directly.
		return realityConnWrapper{c}, nil
	}, func(a any) {
		stack := debug.Stack()
		log.Errorln("reality server panic: %s\n%s", a, stack)
	})
}

type realityConnWrapper struct {
	*utls.Conn
}

func (c realityConnWrapper) Upstream() any {
	return c.Conn
}

func (c realityConnWrapper) CloseWrite() error {
	return c.Conn.CloseWrite()
}

func (c realityConnWrapper) ReaderReplaceable() bool {
	return true
}

func (c realityConnWrapper) WriterReplaceable() bool {
	return true
}
