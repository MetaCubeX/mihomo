package config

import (
	"encoding/json"

	"github.com/metacubex/mihomo/listener/sing"
)

// SudokuServer describes a Sudoku inbound server configuration.
// It is internal to the listener layer and mainly used for logging and wiring.
type SudokuServer struct {
	Enable                 bool     `json:"enable"`
	Listen                 string   `json:"listen"`
	Key                    string   `json:"key"`
	AEADMethod             string   `json:"aead-method,omitempty"`
	PaddingMin             *int     `json:"padding-min,omitempty"`
	PaddingMax             *int     `json:"padding-max,omitempty"`
	TableType              string   `json:"table-type,omitempty"`
	HandshakeTimeoutSecond *int     `json:"handshake-timeout,omitempty"`
	EnablePureDownlink     *bool    `json:"enable-pure-downlink,omitempty"`
	CustomTable            string   `json:"custom-table,omitempty"`
	CustomTables           []string `json:"custom-tables,omitempty"`
	DisableHTTPMask        bool     `json:"disable-http-mask,omitempty"`
	HTTPMaskMode           string   `json:"http-mask-mode,omitempty"`
	PathRoot               string   `json:"path-root,omitempty"`

	// mihomo private extension (not the part of standard Sudoku protocol)
	MuxOption sing.MuxOption `json:"mux-option,omitempty"`
}

func (s SudokuServer) String() string {
	b, _ := json.Marshal(s)
	return string(b)
}
