package obfs

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/pool"
)

func TestHTTPObfsFragmentedResponse(t *testing.T) {
	header := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n"
	tests := []struct {
		name    string
		chunks  []string
		wantErr error
	}{
		{"whole", []string{header + "abcd"}, nil},
		{"split_header", []string{header[:20], header[20:] + "abcd"}, nil},
		{"split_delimiter", []string{header[:len(header)-2], header[len(header)-2:] + "abcd"}, nil},
		{"header_only_first", []string{header, "abcd"}, nil},
		{"truncated", []string{header[:20]}, io.EOF},
		{"oversized", []string{strings.Repeat("x", pool.RelayBufferSize+1)}, io.ErrShortBuffer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			client.SetReadDeadline(time.Now().Add(time.Second))
			go func() {
				defer server.Close()
				for _, chunk := range tt.chunks {
					if _, err := io.WriteString(server, chunk); err != nil {
						return
					}
				}
			}()
			buf := make([]byte, 4)
			_, err := io.ReadFull(NewHTTPObfs(client, "localhost", "80"), buf)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && string(buf) != "abcd" {
				t.Fatalf("payload %q", buf)
			}
		})
	}
}
