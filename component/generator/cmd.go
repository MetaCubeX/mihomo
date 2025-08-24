package generator

import (
	"encoding/base64"
	"fmt"

	"github.com/metacubex/mihomo/component/ech"
	"github.com/metacubex/mihomo/transport/vless/encryption"

	"github.com/gofrs/uuid/v5"
)

func Main(args []string) {
	if len(args) < 1 {
		panic("Using: generate uuid/reality-keypair/wg-keypair/ech-keypair/vless-mlkem768/vless-x25519")
	}
	switch args[0] {
	case "uuid":
		newUUID, err := uuid.NewV4()
		if err != nil {
			panic(err)
		}
		fmt.Println(newUUID.String())
	case "reality-keypair":
		privateKey, err := GenX25519PrivateKey()
		if err != nil {
			panic(err)
		}
		fmt.Println("PrivateKey: " + base64.RawURLEncoding.EncodeToString(privateKey.Bytes()))
		fmt.Println("PublicKey: " + base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()))
	case "wg-keypair":
		privateKey, err := GenX25519PrivateKey()
		if err != nil {
			panic(err)
		}
		fmt.Println("PrivateKey: " + base64.StdEncoding.EncodeToString(privateKey.Bytes()))
		fmt.Println("PublicKey: " + base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes()))
	case "ech-keypair":
		if len(args) < 2 {
			panic("Using: generate ech-keypair <plain_server_name>")
		}
		configBase64, keyPem, err := ech.GenECHConfig(args[1])
		if err != nil {
			panic(err)
		}
		fmt.Println("Config:", configBase64)
		fmt.Println("Key:", keyPem)
	case "vless-mlkem768":
		var seed string
		if len(args) > 1 {
			seed = args[1]
		}
		seedBase64, clientBase64, hash32Base64, err := encryption.GenMLKEM768(seed)
		if err != nil {
			panic(err)
		}
		fmt.Println("Seed: " + seedBase64)
		fmt.Println("Client: " + clientBase64)
		fmt.Println("Hash32: " + hash32Base64)
	case "vless-x25519":
		var privateKey string
		if len(args) > 1 {
			privateKey = args[1]
		}
		privateKeyBase64, passwordBase64, hash32Base64, err := encryption.GenX25519(privateKey)
		if err != nil {
			panic(err)
		}
		fmt.Println("PrivateKey: " + privateKeyBase64)
		fmt.Println("Password: " + passwordBase64)
		fmt.Println("Hash32: " + hash32Base64)
	}
}
