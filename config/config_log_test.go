package config

import "testing"

func TestLogTimestampConfig(t *testing.T) {
	if !DefaultRawConfig().LogTimestamp {
		t.Fatal("console log timestamps should be enabled by default")
	}

	raw, err := UnmarshalRawConfig([]byte("log-timestamp: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	general, err := parseGeneral(raw)
	if err != nil {
		t.Fatal(err)
	}
	if general.LogTimestamp {
		t.Fatal("log-timestamp: false was not applied")
	}
}
