package inbound_test

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/stretchr/testify/assert"
)

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
}

func TestInboundSudoku_Padding(t *testing.T) {
	key := "test_key_padding"
	min := 10
	max := 100
	inboundOptions := inbound.SudokuOption{
		Key:        key,
		PaddingMin: &min,
		PaddingMax: &max,
	}
	outboundOptions := outbound.SudokuOption{
		Key:        key,
		PaddingMin: &min,
		PaddingMax: &max,
	}
	testInboundSudoku(t, inboundOptions, outboundOptions)
}
