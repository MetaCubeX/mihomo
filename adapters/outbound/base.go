package adapters

import (
	"encoding/json"

	C "github.com/Dreamacro/clash/constant"
)

type Base struct {
	name string
	tp   C.AdapterType
}

func (b *Base) Name() string {
	return b.name
}

func (b *Base) Type() C.AdapterType {
	return b.tp
}

func (b *Base) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"type": b.Type().String(),
	})
}
