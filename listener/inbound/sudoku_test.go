package inbound_test

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/sudoku"
	"github.com/stretchr/testify/assert"
)

var sudokuPrivateKey, sudokuPublicKey, _ = sudoku.GenKeyPair()

func testInboundSudoku(t *testing.T, inboundOptions inbound.SudokuOption, outboundOptions outbound.SudokuOption) {
	t.Parallel()

	inboundOptions.BaseOption = inbound.BaseOption{
		NameStr: "sudoku_inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	in, err := inbound.NewSudoku(&inboundOptions)
	if !assert.NoError(t, err) {
		return
	}

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	err = in.Listen(tunnel)
	if !assert.NoError(t, err) {
		return
	}
	defer in.Close()

	addrPort, err := netip.ParseAddrPort(in.Address())
	if !assert.NoError(t, err) {
		return
	}

	outboundOptions.Name = "sudoku_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())

	out, err := outbound.NewSudoku(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)

	testSingMux(t, tunnel, out)
}

func TestInboundSudoku_Basic(t *testing.T) {
	key := "test_key"
	inboundOptions := inbound.SudokuOption{
		Key: key,
	}
	outboundOptions := outbound.SudokuOption{
		Key: key,
	}
	testInboundSudoku(t, inboundOptions, outboundOptions)

	t.Run("ed25519key", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.Key = sudokuPublicKey
		outboundOptions.Key = sudokuPrivateKey
		testInboundSudoku(t, inboundOptions, outboundOptions)
	})
}

func TestInboundSudoku_Entropy(t *testing.T) {
	key := "test_key_entropy"
	inboundOptions := inbound.SudokuOption{
		Key:       key,
		TableType: "prefer_entropy",
	}
	outboundOptions := outbound.SudokuOption{
		Key:       key,
		TableType: "prefer_entropy",
	}
	testInboundSudoku(t, inboundOptions, outboundOptions)

	t.Run("ed25519key", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.Key = sudokuPublicKey
		outboundOptions.Key = sudokuPrivateKey
		testInboundSudoku(t, inboundOptions, outboundOptions)
	})
}

func TestInboundSudoku_Padding(t *testing.T) {
	key := "test_key_padding"
	paddingMin := 10
	paddingMax := 100
	inboundOptions := inbound.SudokuOption{
		Key:        key,
		PaddingMin: &paddingMin,
		PaddingMax: &paddingMax,
	}
	outboundOptions := outbound.SudokuOption{
		Key:        key,
		PaddingMin: &paddingMin,
		PaddingMax: &paddingMax,
	}
	testInboundSudoku(t, inboundOptions, outboundOptions)

	t.Run("ed25519key", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.Key = sudokuPublicKey
		outboundOptions.Key = sudokuPrivateKey
		testInboundSudoku(t, inboundOptions, outboundOptions)
	})
}

func TestInboundSudoku_PackedDownlink(t *testing.T) {
	key := "test_key_packed"
	enablePure := false
	inboundOptions := inbound.SudokuOption{
		Key:                key,
		EnablePureDownlink: &enablePure,
	}
	outboundOptions := outbound.SudokuOption{
		Key:                key,
		EnablePureDownlink: &enablePure,
	}
	testInboundSudoku(t, inboundOptions, outboundOptions)

	t.Run("ed25519key", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.Key = sudokuPublicKey
		outboundOptions.Key = sudokuPrivateKey
		testInboundSudoku(t, inboundOptions, outboundOptions)
	})
}

func TestInboundSudoku_CustomTable(t *testing.T) {
	key := "test_key_custom"
	custom := "xpxvvpvv"
	inboundOptions := inbound.SudokuOption{
		Key:         key,
		TableType:   "prefer_entropy",
		CustomTable: custom,
	}
	outboundOptions := outbound.SudokuOption{
		Key:         key,
		TableType:   "prefer_entropy",
		CustomTable: custom,
	}
	testInboundSudoku(t, inboundOptions, outboundOptions)

	t.Run("ed25519key", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.Key = sudokuPublicKey
		outboundOptions.Key = sudokuPrivateKey
		testInboundSudoku(t, inboundOptions, outboundOptions)
	})
}

func TestInboundSudoku_HTTPMaskMode(t *testing.T) {
	key := "test_key_http_mask_mode"

	for _, mode := range []string{"legacy", "stream", "poll", "auto"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			inboundOptions := inbound.SudokuOption{
				Key:          key,
				HTTPMaskMode: mode,
			}
			outboundOptions := outbound.SudokuOption{
				Key:          key,
				HTTPMask:     true,
				HTTPMaskMode: mode,
			}
			testInboundSudoku(t, inboundOptions, outboundOptions)
		})
	}
}
