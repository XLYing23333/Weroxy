//go:build !windows

package clientservice

import (
	"context"

	"weroxy/client/internal/menu"
	"weroxy/client/internal/tunnel"
)

func Run(ctx context.Context, opt tunnel.Options) error { return tunnel.Run(ctx, opt) }

func Manage(ctx context.Context, action, configPath string) int {
	return menu.Service(ctx, action, menu.Option{ConfigPath: configPath})
}
