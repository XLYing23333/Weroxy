//go:build !linux

package upgrade

import (
	"context"
	"errors"
)

func ApplyPackage(context.Context, string, string, string, string, string, string) error {
	return errors.New("本轮原生安装包仅支持 Linux")
}
