package script

/*
#include "clash_module.h"

extern const char *resolveIPCallbackFn(const char *host);

void
go_set_resolve_ip_callback() {
	set_resolve_ip_callback(resolveIPCallbackFn);
}

extern const char *geoipCallbackFn(const char *ip);

void
go_set_geoip_callback() {
	set_geoip_callback(geoipCallbackFn);
}

extern const int ruleProviderCallbackFn(const char *provider_name, struct Metadata *metadata);

void
go_set_rule_provider_callback() {
	set_rule_provider_callback(ruleProviderCallbackFn);
}

extern void logCallbackFn(const char *msg);

void
go_set_log_callback() {
	set_log_callback(logCallbackFn);
}
*/
import "C"
import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

const ClashScriptModuleName = C.CLASH_SCRIPT_MODULE_NAME

var lock sync.Mutex

type PyObject C.PyObject

func togo(cobject *C.PyObject) *PyObject {
	return (*PyObject)(cobject)
}

func toc(object *PyObject) *C.PyObject {
	return (*C.PyObject)(object)
}

func (pyObject *PyObject) IncRef() {
	C.Py_IncRef(toc(pyObject))
}

func (pyObject *PyObject) DecRef() {
	C.Py_DecRef(toc(pyObject))
}

func (pyObject *PyObject) Clear() {
	C.py_clear(toc(pyObject))
}

// Py_Initialize initialize Python3
func Py_Initialize(program string, path string) error {
	lock.Lock()
	defer lock.Unlock()

	if C.Py_IsInitialized() != 0 {
		if pyThreadState != nil {
			PyEval_RestoreThread(pyThreadState)
		}
		C.finalize_Python()
	}

	path = strings.ReplaceAll(path, "\\", "/")
	cPath := C.CString(path)
	//defer C.free(unsafe.Pointer(cPath))

	C.init_python(C.CString(program), cPath)
	err := PyLastError()

	if err != nil {
		if C.Py_IsInitialized() != 0 {
			C.finalize_Python()
			_ = os.RemoveAll(constant.Path.ScriptDir())
		}
		return err
	} else if C.Py_IsInitialized() == 0 {
		err = errors.New("initialized script module failure")
		return err
	}

	initPython3Callback()
	return nil
}

func Py_IsInitialized() bool {
	lock.Lock()
	defer lock.Unlock()

	return C.Py_IsInitialized() != 0
}

func Py_Finalize() {
	lock.Lock()
	defer lock.Unlock()

	if C.Py_IsInitialized() != 0 {
		if pyThreadState != nil {
			PyEval_RestoreThread(pyThreadState)
		}
		C.finalize_Python()
		_ = os.RemoveAll(constant.Path.ScriptDir())
		log.Warnln("Clash clean up script mode.")
	}
}

//Py_GetVersion get
func Py_GetVersion() string {
	cversion := C.Py_GetVersion()
	return strings.Split(C.GoString(cversion), "\n")[0]
}

// loadPyFunc loads a Python function by module and function name
func loadPyFunc(moduleName, funcName string) (*C.PyObject, error) {
	// Convert names to C char*
	cMod := C.CString(moduleName)
	cFunc := C.CString(funcName)

	// Free memory allocated by C.CString
	defer func() {
		C.free(unsafe.Pointer(cMod))
		C.free(unsafe.Pointer(cFunc))
	}()

	fnc := C.load_func(cMod, cFunc)
	if fnc == nil {
		return nil, PyLastError()
	}

	return fnc, nil
}

//PyLastError python last error
func PyLastError() error {
	cp := C.py_last_error()
	if cp == nil {
		return nil
	}

	return errors.New(C.GoString(cp))
}

func LoadShortcutFunction(shortcut string) (*PyObject, error) {
	fnc, err := loadPyFunc(ClashScriptModuleName, shortcut)
	if err != nil {
		return nil, err
	}
	return togo(fnc), nil
}

func LoadMainFunction() error {
	C.load_main_func()
	err := PyLastError()
	if err != nil {
		return err
	}
	return nil
}

//CallPyMainFunction call python script main function
//return the proxy adapter name.
func CallPyMainFunction(mtd *constant.Metadata) (string, error) {
	_type := C.CString(mtd.Type.String())
	network := C.CString(mtd.NetWork.String())
	processName := C.CString(mtd.Process)
	host := C.CString(mtd.Host)

	srcPortGo, _ := strconv.ParseUint(mtd.SrcPort, 10, 16)
	dstPortGo, _ := strconv.ParseUint(mtd.DstPort, 10, 16)
	srcPort := C.ushort(srcPortGo)
	dstPort := C.ushort(dstPortGo)

	dstIpGo := ""
	srcIpGo := ""
	if mtd.SrcIP != nil {
		srcIpGo = mtd.SrcIP.String()
	}
	if mtd.DstIP != nil {
		dstIpGo = mtd.DstIP.String()
	}
	srcIp := C.CString(srcIpGo)
	dstIp := C.CString(dstIpGo)

	defer func() {
		C.free(unsafe.Pointer(_type))
		C.free(unsafe.Pointer(network))
		C.free(unsafe.Pointer(processName))
		C.free(unsafe.Pointer(host))
		C.free(unsafe.Pointer(srcIp))
		C.free(unsafe.Pointer(dstIp))
	}()

	runtime.LockOSThread()
	gilState := PyGILState_Ensure()
	defer PyGILState_Release(gilState)

	cRs := C.call_main(_type, network, processName, host, srcIp, srcPort, dstIp, dstPort)

	rs := C.GoString(cRs)
	if rs == "-1" {
		err := PyLastError()
		if err != nil {
			log.Errorln("[Script] script code error: %s", err.Error())
			killSelf()
			return "", fmt.Errorf("script code error: %w", err)
		} else {
			return "", fmt.Errorf("script code error, result: %v", rs)
		}
	}

	return rs, nil
}

//CallPyShortcut call python script shortcuts function
//param: shortcut name
//return the match result.
func CallPyShortcut(fn *PyObject, mtd *constant.Metadata) (bool, error) {
	_type := C.CString(mtd.Type.String())
	network := C.CString(mtd.NetWork.String())
	processName := C.CString(mtd.Process)
	host := C.CString(mtd.Host)

	srcPortGo, _ := strconv.ParseUint(mtd.SrcPort, 10, 16)
	dstPortGo, _ := strconv.ParseUint(mtd.DstPort, 10, 16)
	srcPort := C.ushort(srcPortGo)
	dstPort := C.ushort(dstPortGo)

	dstIpGo := ""
	srcIpGo := ""
	if mtd.SrcIP != nil {
		srcIpGo = mtd.SrcIP.String()
	}
	if mtd.DstIP != nil {
		dstIpGo = mtd.DstIP.String()
	}
	srcIp := C.CString(srcIpGo)
	dstIp := C.CString(dstIpGo)

	defer func() {
		C.free(unsafe.Pointer(_type))
		C.free(unsafe.Pointer(network))
		C.free(unsafe.Pointer(processName))
		C.free(unsafe.Pointer(host))
		C.free(unsafe.Pointer(srcIp))
		C.free(unsafe.Pointer(dstIp))
	}()

	runtime.LockOSThread()
	gilState := PyGILState_Ensure()
	defer PyGILState_Release(gilState)

	cRs := C.call_shortcut(toc(fn), _type, network, processName, host, srcIp, srcPort, dstIp, dstPort)

	rs := int(cRs)
	if rs == -1 {
		err := PyLastError()
		if err != nil {
			log.Errorln("[Script] script shortcut code error: %s", err.Error())
			killSelf()
			return false, fmt.Errorf("script shortcut code error: %w", err)
		} else {
			return false, fmt.Errorf("script shortcut code error: result: %d", rs)
		}
	}

	if rs == 1 {
		return true, nil
	} else {
		return false, nil
	}
}

func initPython3Callback() {
	C.go_set_resolve_ip_callback()
	C.go_set_geoip_callback()
	C.go_set_rule_provider_callback()
	C.go_set_log_callback()
}

//NewClashPyContext new clash context for python
func NewClashPyContext(ruleProvidersName []string) error {
	length := len(ruleProvidersName)
	cStringArr := make([]*C.char, length)
	for i, v := range ruleProvidersName {
		cStringArr[i] = C.CString(v)
		defer C.free(unsafe.Pointer(cStringArr[i]))
	}

	cArrPointer := unsafe.Pointer(nil)
	if length > 0 {
		cArrPointer = unsafe.Pointer(&cStringArr[0])
	}

	rs := int(C.new_clash_py_context((**C.char)(cArrPointer), C.int(length)))

	if rs == 0 {
		err := PyLastError()
		return fmt.Errorf("new script module context failure: %s", err.Error())
	}

	return nil
}

func killSelf() {
	p, err := os.FindProcess(os.Getpid())

	if err != nil {
		os.Exit(int(syscall.SIGINT))
		return
	}

	_ = p.Signal(syscall.SIGINT)
}
