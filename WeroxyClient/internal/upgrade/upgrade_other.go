//go:build !linux && !windows

package upgrade

import (
	"context"
	"errors"
)

func Apply(context.Context, string, string, string, string) error {
	return errors.New("当前平台尚不支持服务原子升级")
}
