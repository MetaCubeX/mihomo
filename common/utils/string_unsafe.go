package utils

import "unsafe"

// sliceHeader is equivalent to reflect.SliceHeader, but represents the pointer
// to the underlying array as unsafe.Pointer rather than uintptr, allowing
// sliceHeaders to be directly converted to slice objects.
type sliceHeader struct {
	Data unsafe.Pointer
	Len  int
	Cap  int
}

// slice returns a slice whose underlying array starts at ptr an which length
// and capacity are len.
func slice[T any](ptr *T, length int) []T {
	var s []T
	hdr := (*sliceHeader)(unsafe.Pointer(&s))
	hdr.Data = unsafe.Pointer(ptr)
	hdr.Len = length
	hdr.Cap = length
	return s
}

// stringHeader is equivalent to reflect.StringHeader, but represents the
// pointer to the underlying array as unsafe.Pointer rather than uintptr,
// allowing StringHeaders to be directly converted to strings.
type stringHeader struct {
	Data unsafe.Pointer
	Len  int
}

// ImmutableBytesFromString is equivalent to []byte(s), except that it uses the
// same memory backing s instead of making a heap-allocated copy. This is only
// valid if the returned slice is never mutated.
func ImmutableBytesFromString(s string) []byte {
	shdr := (*stringHeader)(unsafe.Pointer(&s))
	return slice((*byte)(shdr.Data), shdr.Len)
}

// StringFromImmutableBytes is equivalent to string(bs), except that it uses
// the same memory backing bs instead of making a heap-allocated copy. This is
// only valid if bs is never mutated after StringFromImmutableBytes returns.
func StringFromImmutableBytes(bs []byte) string {
	// This is cheaper than messing with StringHeader and SliceHeader, which as
	// of this writing produces many dead stores of zeroes. Compare
	// strings.Builder.String().
	return *(*string)(unsafe.Pointer(&bs))
}
