package outbound

import (
	"strings"
	"testing"

	"github.com/metacubex/mihomo/common/structure"
)

func TestXHTTPReceiveWindowValidation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		up        int
		down      *int
		wantError string
	}{
		{name: "defaults"},
		{name: "inherited", up: 8 << 20},
		{name: "download override", up: 4 << 20, down: windowInt(16 << 20)},
		{name: "explicit default", up: 8 << 20, down: windowInt(0)},
		{name: "negative", up: -1, wantError: "xhttp h2-max"},
		{name: "negative download", down: windowInt(-1), wantError: "download-settings.h2-max"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewVless(VlessOption{
				Name: "window-test", Server: "192.0.2.1", Port: 443,
				UUID: "00000000-0000-4000-8000-000000000001", Network: "xhttp",
				XHTTPOpts: XHTTPOptions{Mode: "stream-up", H2MaxReceiveBufferPerStream: tc.up,
					DownloadSettings: &XHTTPDownloadSettings{H2MaxReceiveBufferPerStream: tc.down}},
			})
			if tc.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("error = %v, want %q", err, tc.wantError)
			}
		})
	}
}

func windowInt(value int) *int { return &value }

func TestXHTTPReceiveWindowDecode(t *testing.T) {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true})
	for _, tc := range []struct {
		name string
		down map[string]any
		want *int
	}{
		{"inherit", map[string]any{}, nil},
		{"override", map[string]any{"h2-max-receive-buffer-per-stream": 16 << 20}, windowInt(16 << 20)},
		{"reset", map[string]any{"h2-max-receive-buffer-per-stream": 0}, windowInt(0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var option VlessOption
			err := decoder.Decode(map[string]any{"name": "window-test", "server": "192.0.2.1", "port": 443,
				"uuid": "00000000-0000-4000-8000-000000000001", "xhttp-opts": map[string]any{
					"h2-max-receive-buffer-per-stream": 8 << 20, "download-settings": tc.down,
				}}, &option)
			if err != nil {
				t.Fatal(err)
			}
			if option.XHTTPOpts.H2MaxReceiveBufferPerStream != 8<<20 {
				t.Fatal("main window not decoded")
			}
			got := option.XHTTPOpts.DownloadSettings.H2MaxReceiveBufferPerStream
			if (got == nil) != (tc.want == nil) || got != nil && *got != *tc.want {
				t.Fatalf("download window = %v, want %v", got, tc.want)
			}
		})
	}
}
