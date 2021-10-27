package script

/*
#include "clash_module.h"
*/
import "C"
import (
	"net"
	"strconv"
	"strings"
	"unsafe"

	"github.com/Dreamacro/clash/component/mmdb"
	"github.com/Dreamacro/clash/component/resolver"
	"github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

var (
	ruleProviders = map[string]constant.Rule{}
	pyThreadState *PyThreadState
)

func UpdateRuleProviders(rpd map[string]constant.Rule) {
	ruleProviders = rpd
	if Py_IsInitialized() {
		pyThreadState = PyEval_SaveThread()
	}
}

//export resolveIPCallbackFn
func resolveIPCallbackFn(cHost *C.char) *C.char {
	host := C.GoString(cHost)
	if len(host) == 0 {
		cip := C.CString("")
		defer C.free(unsafe.Pointer(cip))
		return cip
	}
	if ip, err := resolver.ResolveIP(host); err == nil {
		cip := C.CString(ip.String())
		defer C.free(unsafe.Pointer(cip))
		return cip
	} else {
		log.Errorln("[Script] resolve ip error: %s", err.Error())
		cip := C.CString("")
		defer C.free(unsafe.Pointer(cip))
		return cip
	}
}

//export geoipCallbackFn
func geoipCallbackFn(cIP *C.char) *C.char {
	dstIP := net.ParseIP(C.GoString(cIP))

	if dstIP == nil {
		emptyC := C.CString("")
		defer C.free(unsafe.Pointer(emptyC))

		return emptyC
	}

	if dstIP.IsPrivate() || constant.TunBroadcastAddr.Equal(dstIP) {
		lanC := C.CString("LAN")
		defer C.free(unsafe.Pointer(lanC))

		return lanC
	}

	record, _ := mmdb.Instance().Country(dstIP)

	rc := C.CString(strings.ToUpper(record.Country.IsoCode))
	defer C.free(unsafe.Pointer(rc))

	return rc
}

//export ruleProviderCallbackFn
func ruleProviderCallbackFn(cProviderName *C.char, cMetadata *C.struct_Metadata) C.int {
	//_type := C.GoString(cMetadata._type)
	//network := C.GoString(cMetadata.network)
	processName := C.GoString(cMetadata.process_name)
	host := C.GoString(cMetadata.host)
	srcIp := C.GoString(cMetadata.src_ip)
	srcPort := strconv.Itoa(int(cMetadata.src_port))
	dstIp := C.GoString(cMetadata.dst_ip)
	dstPort := strconv.Itoa(int(cMetadata.dst_port))

	dst := net.ParseIP(dstIp)
	addrType := constant.AtypDomainName

	if dst != nil {
		if dst.To4() != nil {
			addrType = constant.AtypIPv4
		} else {
			addrType = constant.AtypIPv6
		}
	}

	metadata := &constant.Metadata{
		Process:  processName,
		SrcIP:    net.ParseIP(srcIp),
		DstIP:    dst,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		AddrType: addrType,
		Host:     host,
	}

	providerName := C.GoString(cProviderName)

	rule, ok := ruleProviders[providerName]
	if !ok {
		log.Warnln("[Script] rule provider [%s] not found", providerName)
		return C.int(0)
	}

	if strings.HasPrefix(providerName, "geosite:") {
		if len(host) == 0 {
			return C.int(0)
		}
		metadata.AddrType = constant.AtypDomainName
	}

	rs := rule.Match(metadata)

	if rs {
		return C.int(1)
	}
	return C.int(0)
}

//export logCallbackFn
func logCallbackFn(msg *C.char) {

	log.Infoln(C.GoString(msg))
}
