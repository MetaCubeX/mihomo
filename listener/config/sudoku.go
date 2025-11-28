package config

import "encoding/json"

// SudokuServer describes a Sudoku inbound server configuration.
// It is internal to the listener layer and mainly used for logging and wiring.
type SudokuServer struct {
	Enable                 bool   `json:"enable"`
	Listen                 string `json:"listen"`
	Key                    string `json:"key"`
	AEADMethod             string `json:"aead-method,omitempty"`
	PaddingMin             *int   `json:"padding-min,omitempty"`
	PaddingMax             *int   `json:"padding-max,omitempty"`
	Seed                   string `json:"seed,omitempty"`
	TableType              string `json:"table-type,omitempty"`
	HandshakeTimeoutSecond *int   `json:"handshake-timeout,omitempty"`
}

func (s SudokuServer) String() string {
	b, _ := json.Marshal(s)
	return string(b)
}
