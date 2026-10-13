package xhttp

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func TestEmptyPaddingValidation(t *testing.T) {
	invalid := Config{XPaddingBytes: "invalid"}
	if invalid.IsPaddingValid("", 0, 0, PaddingMethodRepeatX) {
		t.Fatal("invalid padding range accepted empty padding")
	}
	for _, method := range []PaddingMethod{"", PaddingMethodRepeatX, PaddingMethodTokenish} {
		for _, test := range []struct {
			name       string
			rangeValue string
			valid      bool
		}{
			{"disabled", "0-0", true},
			{"zero minimum", "0-100", true},
			{"positive minimum", "1-100", false},
			{"default", "", false},
		} {
			t.Run(string(method)+"/"+test.name, func(t *testing.T) {
				config := Config{XPaddingBytes: test.rangeValue}
				r, err := config.GetNormalizedXPaddingBytes()
				if err != nil {
					t.Fatal(err)
				}
				if got := config.IsPaddingValid("", r.Min, r.Max, method); got != test.valid {
					t.Fatalf("empty padding validity = %v, want %v", got, test.valid)
				}
			})
		}
	}
}

func TestStreamOneWithoutPadding(t *testing.T) {
	config := Config{Mode: "stream-one", XPaddingBytes: "0-0"}
	const payload = "stream payload"
	received := make(chan string, 1)
	handler, err := NewServerHandler(ServerOption{
		Config: config,
		ConnHandler: func(conn net.Conn) {
			defer conn.Close()
			data, _ := io.ReadAll(conn)
			received <- string(data)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://example.com/", bytes.NewBufferString(payload))
	if err := config.FillStreamRequest(request, ""); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
	if got := <-received; got != payload {
		t.Fatalf("received %q, want %q", got, payload)
	}
}
