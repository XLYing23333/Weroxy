//go:build windows

package clientservice

import (
	"context"
	"fmt"
	"os"
	"weroxy/client/internal/tunnel"
)

func Run(ctx context.Context, opt tunnel.Options) error { return tunnel.Run(ctx, opt) }
func Manage(context.Context, string, string) int {
	fmt.Fprintln(os.Stderr, "Native service management is Linux only.")
	return 2
}
