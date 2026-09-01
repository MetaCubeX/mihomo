package ebpf

/*
#cgo CFLAGS: -I${SRCDIR}/bpf
#include <stddef.h>
#include "abi.h"
static size_t dae_param_socket_mark_offset(void) { return offsetof(struct dae_param, dae_socket_mark); }
static size_t dae_event_dest_ip_offset(void) { return offsetof(struct dae_event, dip); }
static size_t dae_event_source_port_offset(void) { return offsetof(struct dae_event, sport); }
*/
import "C"

type cLayout struct {
	param, tuple, redirect, direct, event         uintptr
	paramSocketMark, eventDestIP, eventSourcePort uintptr
}

func abiCLayout() cLayout {
	return cLayout{
		param:           C.sizeof_struct_dae_param,
		tuple:           C.sizeof_struct_redirect_tuple,
		redirect:        C.sizeof_struct_redirect_entry,
		direct:          C.sizeof_struct_direct_track_entry,
		event:           C.sizeof_struct_dae_event,
		paramSocketMark: uintptr(C.dae_param_socket_mark_offset()),
		eventDestIP:     uintptr(C.dae_event_dest_ip_offset()),
		eventSourcePort: uintptr(C.dae_event_source_port_offset()),
	}
}
