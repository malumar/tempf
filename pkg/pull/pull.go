package pull

import "sync"

type Pool[T any] struct {
	sync.Pool
	reset func(T) T
}

func (p *Pool[T]) Get() T {
	return p.Pool.Get().(T)
}

func (p *Pool[T]) Put(x T) {
	if p.reset != nil {
		x = p.reset(x)
	}
	p.Pool.Put(x)
}

func New[T any](newF func() T, reset func(T) T) *Pool[T] {
	return &Pool[T]{
		reset: reset,
		Pool: sync.Pool{
			New: func() interface{} {
				return newF()
			},
		},
	}
}
