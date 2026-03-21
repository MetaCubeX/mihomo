package atomic

import (
	"io"
	"os"
	"testing"
)

func TestTypedValue(t *testing.T) {
	{
		var v TypedValue[int]
		got, gotOk := v.LoadOk()
		if got != 0 || gotOk {
			t.Fatalf("LoadOk = (%v, %v), want (0, false)", got, gotOk)
		}
		v.Store(1)
		got, gotOk = v.LoadOk()
		if got != 1 || !gotOk {
			t.Fatalf("LoadOk = (%v, %v), want (1, true)", got, gotOk)
		}
	}

	{
		var v TypedValue[error]
		got, gotOk := v.LoadOk()
		if got != nil || gotOk {
			t.Fatalf("LoadOk = (%v, %v), want (nil, false)", got, gotOk)
		}
		v.Store(io.EOF)
		got, gotOk = v.LoadOk()
		if got != io.EOF || !gotOk {
			t.Fatalf("LoadOk = (%v, %v), want (EOF, true)", got, gotOk)
		}
		err := &os.PathError{}
		v.Store(err)
		got, gotOk = v.LoadOk()
		if got != err || !gotOk {
			t.Fatalf("LoadOk = (%v, %v), want (%v, true)", got, gotOk, err)
		}
		v.Store(nil)
		got, gotOk = v.LoadOk()
		if got != nil || !gotOk {
			t.Fatalf("LoadOk = (%v, %v), want (nil, true)", got, gotOk)
		}
	}

	{
		e1, e2, e3 := io.EOF, &os.PathError{}, &os.PathError{}
		var v TypedValue[error]
		if v.CompareAndSwap(e1, e2) != false {
			t.Fatalf("CompareAndSwap = true, want false")
		}
		if value := v.Load(); value != nil {
			t.Fatalf("Load = (%v), want (%v)", value, nil)
		}
		if v.CompareAndSwap(nil, e1) != true {
			t.Fatalf("CompareAndSwap = false, want true")
		}
		if value := v.Load(); value != e1 {
			t.Fatalf("Load = (%v), want (%v)", value, e1)
		}
		if v.CompareAndSwap(e2, e3) != false {
			t.Fatalf("CompareAndSwap = true, want false")
		}
		if value := v.Load(); value != e1 {
			t.Fatalf("Load = (%v), want (%v)", value, e1)
		}
		if v.CompareAndSwap(e1, e2) != true {
			t.Fatalf("CompareAndSwap = false, want true")
		}
		if value := v.Load(); value != e2 {
			t.Fatalf("Load = (%v), want (%v)", value, e2)
		}
		if v.CompareAndSwap(e3, e2) != false {
			t.Fatalf("CompareAndSwap = true, want false")
		}
		if value := v.Load(); value != e2 {
			t.Fatalf("Load = (%v), want (%v)", value, e2)
		}
		if v.CompareAndSwap(nil, e3) != false {
			t.Fatalf("CompareAndSwap = true, want false")
		}
		if value := v.Load(); value != e2 {
			t.Fatalf("Load = (%v), want (%v)", value, e2)
		}
	}

	{
		c1, c2, c3 := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var v TypedValue[chan struct{}]
		if v.CompareAndSwap(c1, c2) != false {
			t.Fatalf("CompareAndSwap = true, want false")
		}
		if value := v.Load(); value != nil {
			t.Fatalf("Load = (%v), want (%v)", value, nil)
		}
		if v.CompareAndSwap(nil, c1) != true {
			t.Fatalf("CompareAndSwap = false, want true")
		}
		if value := v.Load(); value != c1 {
			t.Fatalf("Load = (%v), want (%v)", value, c1)
		}
		if v.CompareAndSwap(c2, c3) != false {
			t.Fatalf("CompareAndSwap = true, want false")
		}
		if value := v.Load(); value != c1 {
			t.Fatalf("Load = (%v), want (%v)", value, c1)
		}
		if v.CompareAndSwap(c1, c2) != true {
			t.Fatalf("CompareAndSwap = false, want true")
		}
		if value := v.Load(); value != c2 {
			t.Fatalf("Load = (%v), want (%v)", value, c2)
		}
		if v.CompareAndSwap(c3, c2) != false {
			t.Fatalf("CompareAndSwap = true, want false")
		}
		if value := v.Load(); value != c2 {
			t.Fatalf("Load = (%v), want (%v)", value, c2)
		}
		if v.CompareAndSwap(nil, c3) != false {
			t.Fatalf("CompareAndSwap = true, want false")
		}
		if value := v.Load(); value != c2 {
			t.Fatalf("Load = (%v), want (%v)", value, c2)
		}
	}

	{
		c1, c2, c3 := &io.LimitedReader{}, &io.SectionReader{}, &io.SectionReader{}
		var v TypedValue[io.Reader]
		if v.CompareAndSwap(c1, c2) != false {
			t.Fatalf("CompareAndSwap = true, want false")
		}
		if value := v.Load(); value != nil {
			t.Fatalf("Load = (%v), want (%v)", value, nil)
		}
		if v.CompareAndSwap(nil, c1) != true {
			t.Fatalf("CompareAndSwap = false, want true")
		}
		if value := v.Load(); value != c1 {
			t.Fatalf("Load = (%v), want (%v)", value, c1)
		}
		if v.CompareAndSwap(c2, c3) != false {
			t.Fatalf("CompareAndSwap = true, want false")
		}
		if value := v.Load(); value != c1 {
			t.Fatalf("Load = (%v), want (%v)", value, c1)
		}
		if v.CompareAndSwap(c1, c2) != true {
			t.Fatalf("CompareAndSwap = false, want true")
		}
		if value := v.Load(); value != c2 {
			t.Fatalf("Load = (%v), want (%v)", value, c2)
		}
		if v.CompareAndSwap(c3, c2) != false {
			t.Fatalf("CompareAndSwap = true, want false")
		}
		if value := v.Load(); value != c2 {
			t.Fatalf("Load = (%v), want (%v)", value, c2)
		}
		if v.CompareAndSwap(nil, c3) != false {
			t.Fatalf("CompareAndSwap = true, want false")
		}
		if value := v.Load(); value != c2 {
			t.Fatalf("Load = (%v), want (%v)", value, c2)
		}
	}
}
