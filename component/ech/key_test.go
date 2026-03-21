package ech

import (
	"encoding/base64"
	"testing"

	"github.com/metacubex/mihomo/component/ech/echparser"
)

func TestGenECHConfig(t *testing.T) {
	domain := "www.example.com"
	configBase64, _, err := GenECHConfig(domain)
	if err != nil {
		t.Error(err)
	}
	echConfigList, err := base64.StdEncoding.DecodeString(configBase64)
	if err != nil {
		t.Error(err)
	}
	echConfigs, err := echparser.ParseECHConfigList(echConfigList)
	if err != nil {
		t.Error(err)
	}
	if len(echConfigs) == 0 {
		t.Error("no ech config")
	}
	if publicName := string(echConfigs[0].PublicName); publicName != domain {
		t.Error("ech config domain error, expect ", domain, " got", publicName)
	}
}
