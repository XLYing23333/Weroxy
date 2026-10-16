//go:build !linux && !windows

package upgrade

import (
	"context"
	"errors"
)

func Apply(context.Context, string, string, string, string) error {
	return errors.New("Atomic service upgrade is not supported on this platform")
}
