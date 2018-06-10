package observable

func mergeWithBytes(ch <-chan interface{}, buf []byte) chan interface{} {
	out := make(chan interface{})
	go func() {
		defer close(out)
		if len(buf) != 0 {
			out <- buf
		}
		for elm := range ch {
			out <- elm
		}
	}()
	return out
}
