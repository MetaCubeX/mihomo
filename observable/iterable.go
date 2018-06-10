package observable

import (
	"errors"
)

type Iterable <-chan interface{}

func NewIterable(any interface{}) (Iterable, error) {
	switch any := any.(type) {
	case chan interface{}:
		return Iterable(any), nil
	case <-chan interface{}:
		return Iterable(any), nil
	default:
		return nil, errors.New("type error")
	}
}
