//go:build !linux

package upgrade

import (
	"context"
	"errors"
)

func ApplyPackage(context.Context, string, string, string, string, string, string) error {
	return errors.New("Native packages are currently supported only on Linux")
}
