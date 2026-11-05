package convert_test

import (
	"encoding/base64"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	. "github.com/metacubex/mihomo/common/convert"

	"github.com/stretchr/testify/assert"
)

// https://v2.hysteria.network/zh/docs/developers/URI-Scheme/
func TestConvertsV2Ray_normal(t *testing.T) {
	hy2test := "hysteria2://letmein@example.com:8443/?insecure=1&obfs=salamander&obfs-password=gawrgura&pinSHA256=65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726&sni=real.example.com&up=114&down=514&alpn=h3,h4#hy2test"

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
			"fingerprint":      "65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726",
		},
	}

	proxies, err := ConvertsV2Ray([]byte(hy2test))

	assert.Nil(t, err)
	assert.Equal(t, expected, proxies)

	_, err = adapter.ParseProxy(proxies[0])
	assert.NoError(t, err)
}

func TestConvertsV2Ray_hysteria2PortHopping(t *testing.T) {
	uri := "hysteria2://letmein@example.com:443,5000-6000/?sni=example.com#hop"
	proxies, err := ConvertsV2Ray([]byte(uri))
	assert.Nil(t, err)
	assert.Equal(t, "example.com", proxies[0]["server"])
	assert.Equal(t, "443", proxies[0]["port"])
	assert.Equal(t, "443,5000-6000", proxies[0]["ports"])

	_, err = adapter.ParseProxy(proxies[0])
	assert.NoError(t, err)
}

func TestConvertsV2Ray_hysteria2RealmScheme(t *testing.T) {
	uri := "hysteria2+realm://tok3n@rendezvous.example.com:8443/rid42?auth=letmein&stun=stun1:3478&stun=stun2:3478&sni=example.com#realm"
	proxies, err := ConvertsV2Ray([]byte(uri))
	assert.Nil(t, err)
	p := proxies[0]
	assert.Equal(t, "hysteria2", p["type"])
	assert.Equal(t, "letmein", p["password"])
	assert.Equal(t, map[string]any{
		"enable":       true,
		"server-url":   "https://rendezvous.example.com:8443",
		"token":        "tok3n",
		"realm-id":     "rid42",
		"stun-servers": []string{"stun1:3478", "stun2:3478"},
	}, p["realm-opts"])

	_, err = adapter.ParseProxy(p)
	assert.NoError(t, err)
}

func TestConvertsV2RayMieru(t *testing.T) {
	mierusTest := "mierus://user:pass@1.2.3.4?handshake-mode=HANDSHAKE_NO_WAIT&mtu=1400&multiplexing=MULTIPLEXING_HIGH&port=6666&port=9998-9999&port=6489&port=4896&profile=default&protocol=TCP&protocol=TCP&protocol=UDP&protocol=UDP&traffic-pattern=CCoQARoECAEQCiIYCAMQASoIMDAwMTAyMDMqCDA0MDUwNjA3"

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
			"traffic-pattern": "CCoQARoECAEQCiIYCAMQASoIMDAwMTAyMDMqCDA0MDUwNjA3",
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
			"traffic-pattern": "CCoQARoECAEQCiIYCAMQASoIMDAwMTAyMDMqCDA0MDUwNjA3",
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
			"traffic-pattern": "CCoQARoECAEQCiIYCAMQASoIMDAwMTAyMDMqCDA0MDUwNjA3",
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
			"traffic-pattern": "CCoQARoECAEQCiIYCAMQASoIMDAwMTAyMDMqCDA0MDUwNjA3",
		},
	}

	proxies, err := ConvertsV2Ray([]byte(mierusTest))

	assert.Nil(t, err)
	assert.Equal(t, expected, proxies)

	_, err = adapter.ParseProxy(proxies[0])
	assert.NoError(t, err)
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

	_, err = adapter.ParseProxy(proxies[0])
	assert.NoError(t, err)
}

func TestConvertsV2RayMieruFragment(t *testing.T) {
	mierusTest := "mierus://user:pass@example.com?port=443&protocol=TCP&profile=default#myproxy"

	proxies, err := ConvertsV2Ray([]byte(mierusTest))

	assert.Nil(t, err)
	assert.Len(t, proxies, 1)
	assert.Equal(t, "myproxy:443/TCP", proxies[0]["name"])

	_, err = adapter.ParseProxy(proxies[0])
	assert.NoError(t, err)
}

func TestConvertsV2RayVlessRealityVisionTCPWithoutHeaderType(t *testing.T) {
	vlessTest := "vless://a1b2c3d4-eacc-4433-981b-7e5f9a8b@142.98.76.54:34888?encryption=none&security=reality&type=tcp&sni=github.io&fp=chrome&pbk=ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw&sid=6ba85179f3a2b4c5&flow=xtls-rprx-vision#My-VLESS-Reality-Vision"

	proxies, err := ConvertsV2Ray([]byte(vlessTest))

	assert.Nil(t, err)
	assert.Len(t, proxies, 1)
	assert.Equal(t, "tcp", proxies[0]["network"])
	assert.Equal(t, "xtls-rprx-vision", proxies[0]["flow"])
	assert.Equal(t, "none", proxies[0]["encryption"])
	assert.Equal(t, "github.io", proxies[0]["servername"])
	assert.NotContains(t, proxies[0], "http-opts")
	assert.NotContains(t, proxies[0], "h2-opts")

	_, err = adapter.ParseProxy(proxies[0])
	assert.NoError(t, err)
}

func TestConvertsV2RayRealityMLKEM768(t *testing.T) {
	const publicKey = "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw"
	tests := []struct {
		name, query, publicKey string
		want                   any
	}{
		{"absent", "", publicKey, nil},
		{"empty", "&support-x25519mlkem768=", publicKey, nil},
		{"true", "&support-x25519mlkem768=true", publicKey, true},
		{"one", "&support-x25519mlkem768=1", publicKey, true},
		{"false", "&support-x25519mlkem768=false", publicKey, false},
		{"zero", "&support-x25519mlkem768=0", publicKey, false},
		{"invalid", "&support-x25519mlkem768=invalid", publicKey, nil},
		{"no-public-key", "&support-x25519mlkem768=true", "", nil},
	}
	for _, scheme := range []string{"vless", "vmess"} {
		for _, tt := range tests {
			t.Run(scheme+"/"+tt.name, func(t *testing.T) {
				uri := scheme + "://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443" +
					"?security=reality&type=tcp&sid=00112233&pbk=" + tt.publicKey + tt.query
				for _, input := range []string{uri, base64.StdEncoding.EncodeToString([]byte(uri))} {
					proxies, err := ConvertsV2Ray([]byte(input))
					if !assert.NoError(t, err) || !assert.Len(t, proxies, 1) {
						return
					}
					if tt.publicKey == "" {
						assert.NotContains(t, proxies[0], "reality-opts")
					} else {
						expected := map[string]any{
							"public-key": tt.publicKey,
							"short-id":   "00112233",
						}
						if tt.want != nil {
							expected["support-x25519mlkem768"] = tt.want
						}
						assert.Equal(t, expected, proxies[0]["reality-opts"])
					}
					_, err = adapter.ParseProxy(proxies[0])
					assert.NoError(t, err)
				}
			})
		}
	}
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

	_, err = adapter.ParseProxy(proxies[0])
	assert.NoError(t, err)
}

func TestConvertsV2RayVlessHTTPTransportUsesH2Opts(t *testing.T) {
	vlessTest := "vless://uuid@example.com:443?security=tls&type=http&host=cdn.example.com&path=%2Fgrpc#vless-h2"

	proxies, err := ConvertsV2Ray([]byte(vlessTest))

	assert.Nil(t, err)
	assert.Len(t, proxies, 1)
	assert.Equal(t, "h2", proxies[0]["network"])
	assert.Equal(t, map[string]any{
		"host": []string{"cdn.example.com"},
		"path": "/grpc",
	}, proxies[0]["h2-opts"])
	assert.NotContains(t, proxies[0], "http-opts")

	_, err = adapter.ParseProxy(proxies[0])
	assert.NoError(t, err)
}

// Regression test for MetaCubeX/mihomo#2738: the legacy v2rayN-style
// base64-JSON VMess parser must place `host` under h2-opts.host instead
// of stranding it inside a non-existent h2-opts.headers.Host key.
func TestConvertsV2RayVmessBase64H2Transport(t *testing.T) {
	// base64 payload decodes to:
	// {"v":"2","ps":"demo","add":"server.example.com","port":"443",
	//  "id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","scy":"auto",
	//  "net":"h2","type":"none","host":"cdn.example.com","path":"/grpc","tls":"tls"}
	vmessTest := "vmess://eyJ2IjoiMiIsInBzIjoiZGVtbyIsImFkZCI6InNlcnZlci5leGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6ImI4MzEzODFkLTYzMjQtNGQ1My1hZDRmLThjZGE0OGIzMDgxMSIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0IjoiaDIiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiJjZG4uZXhhbXBsZS5jb20iLCJwYXRoIjoiL2dycGMiLCJ0bHMiOiJ0bHMifQ=="

	proxies, err := ConvertsV2Ray([]byte(vmessTest))

	assert.Nil(t, err)
	assert.Len(t, proxies, 1)
	assert.Equal(t, "h2", proxies[0]["network"])
	assert.Equal(t, map[string]any{
		"host": []string{"cdn.example.com"},
		"path": "/grpc",
	}, proxies[0]["h2-opts"])
	assert.NotContains(t, proxies[0], "http-opts")

	_, err = adapter.ParseProxy(proxies[0])
	assert.NoError(t, err)
}

// `net: http` with `type != "http"` is remapped to h2 transport
// at converter.go's network-resolution step, so it must produce the
// same h2-opts shape as `net: h2`. Guards against regression if the
// remap rule is changed later.
func TestConvertsV2RayVmessBase64HTTPRemappedToH2Transport(t *testing.T) {
	// base64 payload decodes to:
	// {"v":"2","ps":"demo-http-remapped","add":"server.example.com","port":"443",
	//  "id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","scy":"auto",
	//  "net":"http","type":"none","host":"cdn.example.com","path":"/grpc","tls":"tls"}
	vmessTest := "vmess://eyJ2IjoiMiIsInBzIjoiZGVtby1odHRwLXJlbWFwcGVkIiwiYWRkIjoic2VydmVyLmV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiYjgzMTM4MWQtNjMyNC00ZDUzLWFkNGYtOGNkYTQ4YjMwODExIiwiYWlkIjoiMCIsInNjeSI6ImF1dG8iLCJuZXQiOiJodHRwIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiY2RuLmV4YW1wbGUuY29tIiwicGF0aCI6Ii9ncnBjIiwidGxzIjoidGxzIn0="

	proxies, err := ConvertsV2Ray([]byte(vmessTest))

	assert.Nil(t, err)
	assert.Len(t, proxies, 1)
	assert.Equal(t, "h2", proxies[0]["network"])
	assert.Equal(t, map[string]any{
		"host": []string{"cdn.example.com"},
		"path": "/grpc",
	}, proxies[0]["h2-opts"])
	assert.NotContains(t, proxies[0], "http-opts")

	_, err = adapter.ParseProxy(proxies[0])
	assert.NoError(t, err)
}

// httpupgrade is a ws-opts mode of the ws transport, not a network of its
// own, so links with type=httpupgrade must become network ws with
// v2ray-http-upgrade set.
func TestConvertsV2RayVlessHTTPUpgrade(t *testing.T) {
	for _, tt := range []struct {
		name     string
		link     string
		fastOpen bool
	}{
		{"without ed", "vless://uuid@example.com:443?security=tls&type=httpupgrade&host=cdn.example.com&path=%2Fup#vless-hu", false},
		{"with ed", "vless://uuid@example.com:443?security=tls&type=httpupgrade&host=cdn.example.com&path=%2Fup&ed=2048#vless-hu", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			proxies, err := ConvertsV2Ray([]byte(tt.link))
			assert.Nil(t, err)
			assert.Len(t, proxies, 1)
			assert.Equal(t, "ws", proxies[0]["network"])

			wsOpts, ok := proxies[0]["ws-opts"].(map[string]any)
			assert.True(t, ok)
			assert.Equal(t, true, wsOpts["v2ray-http-upgrade"])
			assert.Equal(t, "/up", wsOpts["path"])
			assert.Equal(t, "cdn.example.com", wsOpts["headers"].(map[string]any)["Host"])
			if tt.fastOpen {
				assert.Equal(t, true, wsOpts["v2ray-http-upgrade-fast-open"])
			} else {
				assert.NotContains(t, wsOpts, "v2ray-http-upgrade-fast-open")
			}
			assert.NotContains(t, wsOpts, "max-early-data")

			_, err = adapter.ParseProxy(proxies[0])
			assert.NoError(t, err)
		})
	}
}

func TestConvertsV2RayVlessWSNotHTTPUpgrade(t *testing.T) {
	proxies, err := ConvertsV2Ray([]byte("vless://uuid@example.com:443?security=tls&type=ws&host=cdn.example.com&path=%2Fws&ed=2048#vless-ws"))
	assert.Nil(t, err)
	assert.Len(t, proxies, 1)
	assert.Equal(t, "ws", proxies[0]["network"])
	wsOpts := proxies[0]["ws-opts"].(map[string]any)
	assert.NotContains(t, wsOpts, "v2ray-http-upgrade")
	assert.Equal(t, 2048, wsOpts["max-early-data"])
}

func TestConvertsV2RayVmessBase64HTTPUpgrade(t *testing.T) {
	for _, tt := range []struct {
		name     string
		path     string
		fastOpen bool
	}{
		{"without ed", "/up", false},
		{"with ed", "/up?ed=2048", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			payload := `{"v":"2","ps":"vmess-hu","add":"server.example.com","port":"443",` +
				`"id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","scy":"auto",` +
				`"net":"httpupgrade","type":"none","host":"cdn.example.com","path":"` + tt.path + `","tls":"tls"}`
			vmessTest := "vmess://" + base64.StdEncoding.EncodeToString([]byte(payload))

			proxies, err := ConvertsV2Ray([]byte(vmessTest))
			assert.Nil(t, err)
			assert.Len(t, proxies, 1)
			assert.Equal(t, "ws", proxies[0]["network"])

			wsOpts, ok := proxies[0]["ws-opts"].(map[string]any)
			assert.True(t, ok)
			assert.Equal(t, true, wsOpts["v2ray-http-upgrade"])
			assert.Equal(t, "/up", wsOpts["path"])
			assert.Equal(t, map[string]any{"Host": "cdn.example.com"}, wsOpts["headers"])
			if tt.fastOpen {
				assert.Equal(t, true, wsOpts["v2ray-http-upgrade-fast-open"])
			} else {
				assert.NotContains(t, wsOpts, "v2ray-http-upgrade-fast-open")
			}
			assert.NotContains(t, wsOpts, "max-early-data")

			_, err = adapter.ParseProxy(proxies[0])
			assert.NoError(t, err)
		})
	}
}

func TestConvertsV2RayTrojanHTTPUpgrade(t *testing.T) {
	proxies, err := ConvertsV2Ray([]byte("trojan://secret@example.com:443?security=tls&type=httpupgrade&host=cdn.example.com&path=%2Fup#trojan-hu"))
	assert.Nil(t, err)
	assert.Len(t, proxies, 1)
	assert.Equal(t, "ws", proxies[0]["network"])

	wsOpts, ok := proxies[0]["ws-opts"].(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, true, wsOpts["v2ray-http-upgrade"])
	assert.Equal(t, "/up", wsOpts["path"])

	_, err = adapter.ParseProxy(proxies[0])
	assert.NoError(t, err)
}
