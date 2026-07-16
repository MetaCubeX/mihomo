package reality

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestConfigBuildUsesMillisecondsForMaxTimeDifference(t *testing.T) {
	builder, err := (Config{
		Dest:              "127.0.0.1:443",
		PrivateKey:        base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		ServerNames:       []string{"example.com"},
		MaxTimeDifference: 1500,
	}).Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := builder.realityConfig.MaxTimeDiff, 1500*time.Millisecond; got != want {
		t.Fatalf("MaxTimeDiff = %v, want %v", got, want)
	}
}
