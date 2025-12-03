//go:build !go1.24

package maphash

import "unsafe"

func Comparable[T comparable](s Seed, v T) uint64 {
	return comparableHash(*(*seedTyp)(unsafe.Pointer(&s)), v)
}

func comparableHash[T comparable](seed seedTyp, v T) uint64 {
	s := seed.s
	var m map[T]struct{}
	mTyp := iTypeOf(m)
	var hasher func(unsafe.Pointer, uintptr) uintptr
	hasher = (*iMapType)(unsafe.Pointer(mTyp)).Hasher

	p := escape(unsafe.Pointer(&v))

	if ptrSize == 8 {
		return uint64(hasher(p, uintptr(s)))
	}
	lo := hasher(p, uintptr(s))
	hi := hasher(p, uintptr(s>>32))
	return uint64(hi)<<32 | uint64(lo)
}

// WriteComparable adds x to the data hashed by h.
func WriteComparable[T comparable](h *Hash, x T) {
	// writeComparable (not in purego mode) directly operates on h.state
	// without using h.buf. Mix in the buffer length so it won't
	// commute with a buffered write, which either changes h.n or changes
	// h.state.
	hash := (*hashTyp)(unsafe.Pointer(h))
	if hash.n != 0 {
		hash.state.s = comparableHash(hash.state, hash.n)
	}
	hash.state.s = comparableHash(hash.state, x)
}

// go/src/hash/maphash/maphash.go
type hashTyp struct {
	_     [0]func() // not comparable
	seed  seedTyp   // initial seed used for this hash
	state seedTyp   // current hash of all flushed bytes
	buf   [128]byte // unflushed byte buffer
	n     int       // number of unflushed bytes
}

type seedTyp struct {
	s uint64
}

type iTFlag uint8
type iKind uint8
type iNameOff int32

// TypeOff is the offset to a type from moduledata.types.  See resolveTypeOff in runtime.
type iTypeOff int32

type iType struct {
	Size_       uintptr
	PtrBytes    uintptr // number of (prefix) bytes in the type that can contain pointers
	Hash        uint32  // hash of type; avoids computation in hash tables
	TFlag       iTFlag  // extra type information flags
	Align_      uint8   // alignment of variable with this type
	FieldAlign_ uint8   // alignment of struct field with this type
	Kind_       iKind   // enumeration for C
	// function for comparing objects of this type
	// (ptr to object A, ptr to object B) -> ==?
	Equal func(unsafe.Pointer, unsafe.Pointer) bool
	// GCData stores the GC type data for the garbage collector.
	// Normally, GCData points to a bitmask that describes the
	// ptr/nonptr fields of the type. The bitmask will have at
	// least PtrBytes/ptrSize bits.
	// If the TFlagGCMaskOnDemand bit is set, GCData is instead a
	// **byte and the pointer to the bitmask is one dereference away.
	// The runtime will build the bitmask if needed.
	// (See runtime/type.go:getGCMask.)
	// Note: multiple types may have the same value of GCData,
	// including when TFlagGCMaskOnDemand is set. The types will, of course,
	// have the same pointer layout (but not necessarily the same size).
	GCData    *byte
	Str       iNameOff // string form
	PtrToThis iTypeOff // type for pointer to this type, may be zero
}

type iMapType struct {
	iType
	Key   *iType
	Elem  *iType
	Group *iType // internal type representing a slot group
	// function for hashing keys (ptr to key, seed) -> hash
	Hasher func(unsafe.Pointer, uintptr) uintptr
}

func iTypeOf(a any) *iType {
	eface := *(*iEmptyInterface)(unsafe.Pointer(&a))
	// Types are either static (for compiler-created types) or
	// heap-allocated but always reachable (for reflection-created
	// types, held in the central map). So there is no need to
	// escape types. noescape here help avoid unnecessary escape
	// of v.
	return (*iType)(noescape(unsafe.Pointer(eface.Type)))
}

type iEmptyInterface struct {
	Type *iType
	Data unsafe.Pointer
}

// noescape hides a pointer from escape analysis.  noescape is
// the identity function but escape analysis doesn't think the
// output depends on the input.  noescape is inlined and currently
// compiles down to zero instructions.
// USE CAREFULLY!
//
// nolint:all
//
//go:nosplit
//goland:noinspection ALL
func noescape(p unsafe.Pointer) unsafe.Pointer {
	x := uintptr(p)
	return unsafe.Pointer(x ^ 0)
}

var alwaysFalse bool
var escapeSink any

// escape forces any pointers in x to escape to the heap.
func escape[T any](x T) T {
	if alwaysFalse {
		escapeSink = x
	}
	return x
}

// ptrSize is the size of a pointer in bytes - unsafe.Sizeof(uintptr(0)) but as an ideal constant.
// It is also the size of the machine's native word size (that is, 4 on 32-bit systems, 8 on 64-bit).
const ptrSize = 4 << (^uintptr(0) >> 63)

const testComparableAllocations = false
