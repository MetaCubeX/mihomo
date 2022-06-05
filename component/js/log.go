//go:build !no_script

package js

import "github.com/Dreamacro/clash/log"

type JsLog struct {
}

func (j JsLog) Log(s string) {
	log.Infoln("[JS] %s", s)
}

func (j JsLog) Warn(s string) {
	log.Warnln("[JS] %s", s)
}

func (j JsLog) Error(s string) {
	log.Errorln("[JS] %s", s)
}
