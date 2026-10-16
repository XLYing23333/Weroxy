//go:build !linux

package harden

import "errors"

func lock() (func(), error) { return nil, errors.New("不支持的平台") }

func trustedExecutable(string) error { return errors.New("不支持的平台") }
