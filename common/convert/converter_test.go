package convert

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// https://v2.hysteria.network/zh/docs/developers/URI-Scheme/
func TestConvertsV2Ray_normal(t *testing.T) {
	hy2test := "hysteria2://letmein@example.com:8443/?insecure=1&obfs=salamander&obfs-password=gawrgura&pinSHA256=deadbeef&sni=real.example.com&up=114&down=514&alpn=h3,h4#hy2test"

	expected := []map[string]interface{}{
		{
			"name":             "hy2test",
			"type":             "hysteria2",
			"server":           "example.com",
			"port":             "8443",
			"sni":              "real.example.com",
			"obfs":             "salamander",
			"obfs-password":    "gawrgura",
			"alpn":             []string{"h3", "h4"},
			"password":         "letmein",
			"up":               "114",
			"down":             "514",
			"skip-cert-verify": true,
			"fingerprint":      "deadbeef",
		},
	}

	proxies, err := ConvertsV2Ray([]byte(hy2test))

	assert.Nil(t, err)
	assert.Equal(t, expected, proxies)
}

func TestConvertsV2RayMieru(t *testing.T) {
	mierusTest := "mierus://user:pass@1.2.3.4?handshake-mode=HANDSHAKE_NO_WAIT&mtu=1400&multiplexing=MULTIPLEXING_HIGH&port=6666&port=9998-9999&port=6489&port=4896&profile=default&protocol=TCP&protocol=TCP&protocol=UDP&protocol=UDP&traffic-pattern=CCoQAQ"

	expected := []map[string]any{
		{
			"name":            "default:6666/TCP",
			"type":            "mieru",
			"server":          "1.2.3.4",
			"port":            6666,
			"transport":       "TCP",
			"udp":             true,
			"username":        "user",
			"password":        "pass",
			"multiplexing":    "MULTIPLEXING_HIGH",
			"handshake-mode":  "HANDSHAKE_NO_WAIT",
			"traffic-pattern": "CCoQAQ",
		},
		{
			"name":            "default:9998-9999/TCP",
			"type":            "mieru",
			"server":          "1.2.3.4",
			"port-range":      "9998-9999",
			"transport":       "TCP",
			"udp":             true,
			"username":        "user",
			"password":        "pass",
			"multiplexing":    "MULTIPLEXING_HIGH",
			"handshake-mode":  "HANDSHAKE_NO_WAIT",
			"traffic-pattern": "CCoQAQ",
		},
		{
			"name":            "default:6489/UDP",
			"type":            "mieru",
			"server":          "1.2.3.4",
			"port":            6489,
			"transport":       "UDP",
			"udp":             true,
			"username":        "user",
			"password":        "pass",
			"multiplexing":    "MULTIPLEXING_HIGH",
			"handshake-mode":  "HANDSHAKE_NO_WAIT",
			"traffic-pattern": "CCoQAQ",
		},
		{
			"name":            "default:4896/UDP",
			"type":            "mieru",
			"server":          "1.2.3.4",
			"port":            4896,
			"transport":       "UDP",
			"udp":             true,
			"username":        "user",
			"password":        "pass",
			"multiplexing":    "MULTIPLEXING_HIGH",
			"handshake-mode":  "HANDSHAKE_NO_WAIT",
			"traffic-pattern": "CCoQAQ",
		},
	}

	proxies, err := ConvertsV2Ray([]byte(mierusTest))

	assert.Nil(t, err)
	assert.Equal(t, expected, proxies)
}

func TestConvertsV2RayMieruMinimal(t *testing.T) {
	mierusTest := "mierus://user:pass@example.com?port=443&protocol=TCP&profile=simple"

	expected := []map[string]any{
		{
			"name":      "simple:443/TCP",
			"type":      "mieru",
			"server":    "example.com",
			"port":      443,
			"transport": "TCP",
			"udp":       true,
			"username":  "user",
			"password":  "pass",
		},
	}

	proxies, err := ConvertsV2Ray([]byte(mierusTest))

	assert.Nil(t, err)
	assert.Equal(t, expected, proxies)
}

func TestConvertsV2RayMieruFragment(t *testing.T) {
	mierusTest := "mierus://user:pass@example.com?port=443&protocol=TCP&profile=default#myproxy"

	proxies, err := ConvertsV2Ray([]byte(mierusTest))

	assert.Nil(t, err)
	assert.Len(t, proxies, 1)
	assert.Equal(t, "myproxy:443/TCP", proxies[0]["name"])
}

func TestConvertsV2RayVlessRealityVisionTCPWithoutHeaderType(t *testing.T) {
	vlessTest := "vless://a1b2c3d4-eacc-4433-981b-7e5f9a8b@142.98.76.54:34888?encryption=none&security=reality&type=tcp&sni=github.io&fp=chrome&pbk=TifX9kL2mPqRsTuVwXyZ_JdUWw&sid=6ba85179f3a2b4c5&flow=xtls-rprx-vision#My-VLESS-Reality-Vision"

	proxies, err := ConvertsV2Ray([]byte(vlessTest))

	assert.Nil(t, err)
	assert.Len(t, proxies, 1)
	assert.Equal(t, "tcp", proxies[0]["network"])
	assert.Equal(t, "xtls-rprx-vision", proxies[0]["flow"])
	assert.Equal(t, "none", proxies[0]["encryption"])
	assert.Equal(t, "github.io", proxies[0]["servername"])
	assert.NotContains(t, proxies[0], "http-opts")
	assert.NotContains(t, proxies[0], "h2-opts")
}

func TestConvertsV2RayVlessTCPHTTPHeaderType(t *testing.T) {
	vlessTest := "vless://uuid@example.com:443?security=tls&type=tcp&headerType=http&host=cdn.example.com&path=%2Fedge&method=POST#vless-http"

	proxies, err := ConvertsV2Ray([]byte(vlessTest))

	assert.Nil(t, err)
	assert.Len(t, proxies, 1)
	assert.Equal(t, "http", proxies[0]["network"])
	assert.Equal(t, map[string]any{
		"method": "POST",
		"path":   []string{"/edge"},
		"headers": map[string]any{
			"Host": []string{"cdn.example.com"},
		},
	}, proxies[0]["http-opts"])
	assert.NotContains(t, proxies[0], "h2-opts")
}

func TestConvertsV2RayVlessHTTPTransportUsesH2Opts(t *testing.T) {
	vlessTest := "vless://uuid@example.com:443?security=tls&type=http&host=cdn.example.com&path=%2Fgrpc#vless-h2"

	proxies, err := ConvertsV2Ray([]byte(vlessTest))

	assert.Nil(t, err)
	assert.Len(t, proxies, 1)
	assert.Equal(t, "h2", proxies[0]["network"])
	assert.Equal(t, map[string]any{
		"host":    []string{"cdn.example.com"},
		"path":    []string{"/grpc"},
		"headers": map[string]any{},
	}, proxies[0]["h2-opts"])
	assert.NotContains(t, proxies[0], "http-opts")
}
