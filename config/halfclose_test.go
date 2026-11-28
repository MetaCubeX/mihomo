package config

import (
	"strconv"
	"testing"
	"time"
)

func TestTCPHalfCloseTimeout(t *testing.T) {
	for _, test := range []struct {
		name string
		yaml string
		want TCPHalfCloseTimeout
	}{
		{name: "default", yaml: "mode: rule\n"},
		{name: "configured", yaml: "tcp-half-close-timeout:\n  client: 300\n  server: 30\n", want: TCPHalfCloseTimeout{Client: 300, Server: 30}},
		{name: "one_direction", yaml: "tcp-half-close-timeout:\n  server: 30\n", want: TCPHalfCloseTimeout{Server: 30}},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := UnmarshalRawConfig([]byte(test.yaml))
			if err != nil {
				t.Fatal(err)
			}
			general, err := parseGeneral(raw)
			if err != nil {
				t.Fatal(err)
			}
			if general.TCPHalfCloseTimeout != test.want {
				t.Fatalf("got %+v, want %+v", general.TCPHalfCloseTimeout, test.want)
			}
		})
	}
}

func TestTCPHalfCloseTimeoutRejectsInvalidRange(t *testing.T) {
	values := []int{-1}
	if strconv.IntSize == 64 {
		overflow := int64((1<<63-1)/time.Second) + 1
		values = append(values, int(overflow))
	}
	for _, value := range values {
		for _, timeout := range []TCPHalfCloseTimeout{{Client: value}, {Server: value}} {
			if _, err := parseGeneral(&RawConfig{TCPHalfCloseTimeout: timeout}); err == nil {
				t.Fatalf("accepted invalid timeout %+v", timeout)
			}
		}
	}
}
