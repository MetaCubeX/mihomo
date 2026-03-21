package obfs

import (
	"bytes"
	"testing"
)

func TestXPlusObfuscator(t *testing.T) {
	x := NewXPlusObfuscator([]byte("Vaundy"))
	tests := []struct {
		name string
		p    []byte
	}{
		{name: "1", p: []byte("HelloWorld")},
		{name: "2", p: []byte("Regret is just a horrible attempt at time travel that ends with you feeling like crap")},
		{name: "3", p: []byte("To be, or not to be, that is the question:\nWhether 'tis nobler in the mind to suffer\n" +
			"The slings and arrows of outrageous fortune,\nOr to take arms against a sea of troubles\n" +
			"And by opposing end them. To die—to sleep,\nNo more; and by a sleep to say we end")},
		{name: "empty", p: []byte("")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, 10240)
			n := x.Obfuscate(tt.p, buf)
			n2 := x.Deobfuscate(buf[:n], buf[n:])
			if !bytes.Equal(tt.p, buf[n:n+n2]) {
				t.Errorf("Inconsistent deobfuscate result: got %v, want %v", buf[n:n+n2], tt.p)
			}
		})
	}
}
