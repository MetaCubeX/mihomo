package generater

import (
	"encoding/base64"
	"fmt"

	"github.com/gofrs/uuid/v5"
)

func Main(args []string) {
	if len(args) < 1 {
		panic("Using: generate uuid/reality-keypair/wg-keypair")
	}
	switch args[0] {
	case "uuid":
		newUUID, err := uuid.NewV4()
		if err != nil {
			panic(err)
		}
		fmt.Println(newUUID.String())
	case "reality-keypair":
		privateKey, err := GeneratePrivateKey()
		if err != nil {
			panic(err)
		}
		publicKey := privateKey.PublicKey()
		fmt.Println("PrivateKey: " + base64.RawURLEncoding.EncodeToString(privateKey[:]))
		fmt.Println("PublicKey: " + base64.RawURLEncoding.EncodeToString(publicKey[:]))
	case "wg-keypair":
		privateKey, err := GeneratePrivateKey()
		if err != nil {
			panic(err)
		}
		fmt.Println("PrivateKey: " + privateKey.String())
		fmt.Println("PublicKey: " + privateKey.PublicKey().String())
	}
}
