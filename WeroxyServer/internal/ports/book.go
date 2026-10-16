package ports

import (
	"errors"
	"sync"
)

// Book serializes allocation so concurrent callers cannot oversubscribe a pool.
type Book struct {
	mu    sync.Mutex
	pool  Pool
	specs []Spec
	items []Assignment
}

// Try adds one forward when the pool can still satisfy its minimum.
func (b *Book) Try(spec Spec) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	next := append(append([]Spec{}, b.specs...), spec)
	out := Allocate(b.pool, next)
	if reason, ok := out.Rejected[spec.ID]; ok {
		return errors.New(reason)
	}
	for _, accepted := range b.specs {
		if reason, rejected := out.Rejected[accepted.ID]; rejected {
			return errors.New(reason)
		}
	}
	b.specs = next
	b.items = out.Assignments
	return nil
}

// Assignments returns the current bindings.
func (b *Book) Assignments() []Assignment {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Assignment(nil), b.items...)
}
