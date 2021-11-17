package system

import "github.com/Dreamacro/clash/log"

type logger struct{}

func (l *logger) D(format string, args ...interface{}) {
	log.Debugln("[TUN] "+format, args...)
}

func (l *logger) I(format string, args ...interface{}) {
	log.Infoln("[TUN] "+format, args...)
}

func (l *logger) W(format string, args ...interface{}) {
	log.Warnln("[TUN] "+format, args...)
}

func (l *logger) E(format string, args ...interface{}) {
	log.Errorln("[TUN] "+format, args...)
}
