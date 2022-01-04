package mime

import (
	"mime"
)

var consensusMimes = map[string]string{
	// rfc4329: text/javascript is obsolete, so we need to overwrite mime's builtin
	".js": "application/javascript; charset=utf-8",
}

func init() {
	for ext, typ := range consensusMimes {
		mime.AddExtensionType(ext, typ)
	}
}
