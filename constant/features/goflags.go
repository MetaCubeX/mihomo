package features

import "runtime/debug"

var (
	GOARM   string
	GOMIPS  string
	GOAMD64 string
)

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, bs := range info.Settings {
			switch bs.Key {
			case "GOARM":
				GOARM = bs.Value
			case "GOMIPS":
				GOMIPS = bs.Value
			case "GOAMD64":
				GOAMD64 = bs.Value
			}
		}
	}
}
