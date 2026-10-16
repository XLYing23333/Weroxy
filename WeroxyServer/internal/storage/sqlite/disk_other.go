//go:build !linux

package sqlite

import "errors"

func diskAvailable(path string) (uint64, error) { return 0, errors.New("disk probe unsupported") }
