//go:build !linux

package harden

import "errors"

func lock() (func(), error) { return nil, errors.New("Unsupported platform") }

func trustedExecutable(string) error { return errors.New("Unsupported platform") }
