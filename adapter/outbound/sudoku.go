package outbound

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/log"

	"github.com/saba-futai/sudoku/apis"
	"github.com/saba-futai/sudoku/pkg/crypto"
	"github.com/saba-futai/sudoku/pkg/obfs/httpmask"
	"github.com/saba-futai/sudoku/pkg/obfs/sudoku"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
)

type Sudoku struct {
	*Base
	option   *SudokuOption
	table    *sudoku.Table
	baseConf apis.ProtocolConfig
}

type SudokuOption struct {
	BasicOption
	Name       string `proxy:"name"`
	Server     string `proxy:"server"`
	Port       int    `proxy:"port"`
	Key        string `proxy:"key"`
	AEADMethod string `proxy:"aead-method,omitempty"`
	PaddingMin *int   `proxy:"padding-min,omitempty"`
	PaddingMax *int   `proxy:"padding-max,omitempty"`
	TableType  string `proxy:"table-type,omitempty"` // "prefer_ascii" or "prefer_entropy"
	HTTPMask   bool   `proxy:"http-mask,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (s *Sudoku) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	return s.DialContextWithDialer(ctx, dialer.NewDialer(s.DialOptions()...), metadata)
}

// DialContextWithDialer implements C.ProxyAdapter
func (s *Sudoku) DialContextWithDialer(ctx context.Context, d C.Dialer, metadata *C.Metadata) (_ C.Conn, err error) {
	if len(s.option.DialerProxy) > 0 {
		d, err = proxydialer.NewByName(s.option.DialerProxy, d)
		if err != nil {
			return nil, err
		}
	}

	cfg, err := s.buildConfig(metadata)
	if err != nil {
		return nil, err
	}

	c, err := d.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", s.addr, err)
	}

	defer func() {
		safeConnClose(c, err)
	}()

	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}

	c, err = s.streamConn(c, cfg)
	if err != nil {
		return nil, err
	}

	return NewConn(c, s), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (s *Sudoku) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	return nil, C.ErrNotSupport
}

// SupportUOT implements C.ProxyAdapter
func (s *Sudoku) SupportUOT() bool {
	return false // Sudoku protocol only supports TCP
}

// SupportWithDialer implements C.ProxyAdapter
func (s *Sudoku) SupportWithDialer() C.NetWork {
	return C.TCP
}

// ProxyInfo implements C.ProxyAdapter
func (s *Sudoku) ProxyInfo() C.ProxyInfo {
	info := s.Base.ProxyInfo()
	info.DialerProxy = s.option.DialerProxy
	return info
}

func (s *Sudoku) buildConfig(metadata *C.Metadata) (*apis.ProtocolConfig, error) {
	if metadata == nil || metadata.DstPort == 0 || !metadata.Valid() {
		return nil, fmt.Errorf("invalid metadata for sudoku outbound")
	}

	cfg := s.baseConf
	cfg.TargetAddress = metadata.RemoteAddress()

	if err := cfg.ValidateClient(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (s *Sudoku) streamConn(rawConn net.Conn, cfg *apis.ProtocolConfig) (_ net.Conn, err error) {
	if !cfg.DisableHTTPMask {
		if err = httpmask.WriteRandomRequestHeader(rawConn, cfg.ServerAddress); err != nil {
			return nil, fmt.Errorf("write http mask failed: %w", err)
		}
	}

	obfsConn := sudoku.NewConn(rawConn, cfg.Table, cfg.PaddingMin, cfg.PaddingMax, false)
	cConn, err := crypto.NewAEADConn(obfsConn, cfg.Key, cfg.AEADMethod)
	if err != nil {
		return nil, fmt.Errorf("setup crypto failed: %w", err)
	}

	handshake := buildSudokuHandshakePayload(cfg.Key)
	if _, err = cConn.Write(handshake[:]); err != nil {
		cConn.Close()
		return nil, fmt.Errorf("send handshake failed: %w", err)
	}

	if err = writeTargetAddress(cConn, cfg.TargetAddress); err != nil {
		cConn.Close()
		return nil, fmt.Errorf("send target address failed: %w", err)
	}

	return cConn, nil
}

func NewSudoku(option SudokuOption) (*Sudoku, error) {
	if option.Server == "" {
		return nil, fmt.Errorf("server is required")
	}
	if option.Port <= 0 || option.Port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", option.Port)
	}
	if option.Key == "" {
		return nil, fmt.Errorf("key is required")
	}

	tableType := strings.ToLower(option.TableType)
	if tableType == "" {
		tableType = "prefer_ascii"
	}
	if tableType != "prefer_ascii" && tableType != "prefer_entropy" {
		return nil, fmt.Errorf("table-type must be prefer_ascii or prefer_entropy")
	}

	seed := option.Key
	if recoveredFromKey, err := crypto.RecoverPublicKey(option.Key); err == nil {
		seed = crypto.EncodePoint(recoveredFromKey)
	}

	// Use local initTable instead of sudoku.NewTable to control logging
	table := initTable(seed, tableType)

	defaultConf := apis.DefaultConfig()
	paddingMin := defaultConf.PaddingMin
	paddingMax := defaultConf.PaddingMax
	if option.PaddingMin != nil {
		paddingMin = *option.PaddingMin
	}
	if option.PaddingMax != nil {
		paddingMax = *option.PaddingMax
	}
	if option.PaddingMin == nil && option.PaddingMax != nil && paddingMax < paddingMin {
		paddingMin = paddingMax
	}
	if option.PaddingMax == nil && option.PaddingMin != nil && paddingMax < paddingMin {
		paddingMax = paddingMin
	}

	baseConf := apis.ProtocolConfig{
		ServerAddress:           net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
		Key:                     option.Key,
		AEADMethod:              defaultConf.AEADMethod,
		Table:                   table,
		PaddingMin:              paddingMin,
		PaddingMax:              paddingMax,
		HandshakeTimeoutSeconds: defaultConf.HandshakeTimeoutSeconds,
		DisableHTTPMask:         !option.HTTPMask,
	}
	if option.AEADMethod != "" {
		baseConf.AEADMethod = option.AEADMethod
	}

	return &Sudoku{
		Base: &Base{
			name:   option.Name,
			addr:   baseConf.ServerAddress,
			tp:     C.Sudoku,
			udp:    false,
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
		option:   &option,
		table:    table,
		baseConf: baseConf,
	}, nil
}

func buildSudokuHandshakePayload(key string) [16]byte {
	var payload [16]byte
	binary.BigEndian.PutUint64(payload[:8], uint64(time.Now().Unix()))
	hash := sha256.Sum256([]byte(key))
	copy(payload[8:], hash[:8])
	return payload
}

func writeTargetAddress(w io.Writer, rawAddr string) error {
	host, portStr, err := net.SplitHostPort(rawAddr)
	if err != nil {
		return err
	}

	portInt, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return err
	}

	var buf []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, 0x01) // IPv4
			buf = append(buf, ip4...)
		} else {
			buf = append(buf, 0x04) // IPv6
			buf = append(buf, ip...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("domain too long")
		}
		buf = append(buf, 0x03) // domain
		buf = append(buf, byte(len(host)))
		buf = append(buf, host...)
	}

	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(portInt))
	buf = append(buf, portBytes[:]...)

	_, err = w.Write(buf)
	return err
}

// initTable initializes the obfuscation tables with Mihomo logging
// mode: "prefer_ascii" or "prefer_entropy"
func initTable(key string, mode string) *sudoku.Table {
	start := time.Now()
	t := &sudoku.Table{
		DecodeMap: make(map[uint32]byte),
		IsASCII:   mode == "prefer_ascii",
	}

	// Initialize padding pool and encoding logic
	if t.IsASCII {
		// === ASCII Mode (0x20 - 0x7F) ===
		// Payload (Hint): 01vvpppp (Bit 6 is 1) -> 0x40 | ...
		// Padding: 001xxxxx (Bit 6 is 0) -> 0x20 | rand(0-31)
		// Range: Padding [32, 63], Payload [64, 127]

		t.PaddingPool = make([]byte, 0, 32)
		for i := 0; i < 32; i++ {
			// 001xxxxx -> 0x20 + i
			t.PaddingPool = append(t.PaddingPool, byte(0x20+i))
		}
	} else {
		// === Entropy Mode (Legacy) ===
		// Padding: 0x80 (10000xxx) & 0x10 (00010xxx)
		// Payload: Avoids bits 7 and 4 being strictly defined like padding
		t.PaddingPool = make([]byte, 0, 16)
		for i := 0; i < 8; i++ {
			t.PaddingPool = append(t.PaddingPool, byte(0x80+i))
			t.PaddingPool = append(t.PaddingPool, byte(0x10+i))
		}
	}

	// Generate sudoku grids
	allGrids := sudoku.GenerateAllGrids()
	h := sha256.New()
	h.Write([]byte(key))
	seed := int64(binary.BigEndian.Uint64(h.Sum(nil)[:8]))
	rng := rand.New(rand.NewSource(seed))

	shuffledGrids := make([]sudoku.Grid, 288)
	copy(shuffledGrids, allGrids)
	rng.Shuffle(len(shuffledGrids), func(i, j int) {
		shuffledGrids[i], shuffledGrids[j] = shuffledGrids[j], shuffledGrids[i]
	})

	// Pre-calculate combinations
	var combinations [][]int
	var combine func(int, int, []int)
	combine = func(s, k int, c []int) {
		if k == 0 {
			tmp := make([]int, len(c))
			copy(tmp, c)
			combinations = append(combinations, tmp)
			return
		}
		for i := s; i <= 16-k; i++ {
			c = append(c, i)
			combine(i+1, k-1, c)
			c = c[:len(c)-1]
		}
	}
	combine(0, 4, []int{})

	// Build mapping table
	for byteVal := 0; byteVal < 256; byteVal++ {
		targetGrid := shuffledGrids[byteVal]
		for _, positions := range combinations {
			var currentHints [4]byte

			// 1. Calculate Abstract Hints
			var rawParts [4]struct{ val, pos byte }

			for i, pos := range positions {
				val := targetGrid[pos] // 1..4
				rawParts[i] = struct{ val, pos byte }{val, uint8(pos)}
			}

			// Check uniqueness (Sudoku logic)
			matchCount := 0
			for _, g := range allGrids {
				match := true
				for _, p := range rawParts {
					if g[p.pos] != p.val {
						match = false
						break
					}
				}
				if match {
					matchCount++
					if matchCount > 1 {
						break
					}
				}
			}

			if matchCount == 1 {
				// Unique, generate final encoding bytes
				for i, p := range rawParts {
					if t.IsASCII {
						// ASCII Encoding: 01vvpppp
						// vv = val-1 (0..3), pppp = pos (0..15)
						// 0x40 | (vv << 4) | pppp
						currentHints[i] = 0x40 | ((p.val - 1) << 4) | (p.pos & 0x0F)
					} else {
						// Entropy Encoding (Legacy)
						// 0vv0pppp
						// Format: ((val-1) << 5) | pos
						currentHints[i] = ((p.val - 1) << 5) | (p.pos & 0x0F)
					}
				}

				t.EncodeTable[byteVal] = append(t.EncodeTable[byteVal], currentHints)
				// Generate decode key
				key := packHintsToKey(currentHints)
				t.DecodeMap[key] = byte(byteVal)
			}
		}
	}
	log.Infoln("[Sudoku] Tables initialized (%s) in %v", mode, time.Since(start))
	return t
}

func packHintsToKey(hints [4]byte) uint32 {
	// Sorting network for 4 elements (Bubble sort unrolled)
	// Swap if a > b
	if hints[0] > hints[1] {
		hints[0], hints[1] = hints[1], hints[0]
	}
	if hints[2] > hints[3] {
		hints[2], hints[3] = hints[3], hints[2]
	}
	if hints[0] > hints[2] {
		hints[0], hints[2] = hints[2], hints[0]
	}
	if hints[1] > hints[3] {
		hints[1], hints[3] = hints[3], hints[1]
	}
	if hints[1] > hints[2] {
		hints[1], hints[2] = hints[2], hints[1]
	}

	return uint32(hints[0])<<24 | uint32(hints[1])<<16 | uint32(hints[2])<<8 | uint32(hints[3])
}
