// Package yaml provides a common entrance for YAML marshaling and unmarshalling.
package yaml

import (
	"gopkg.in/yaml.v3"
)

func Unmarshal(in []byte, out any) (err error) {
	return yaml.Unmarshal(in, out)
}

func Marshal(in any) (out []byte, err error) {
	return yaml.Marshal(in)
}
