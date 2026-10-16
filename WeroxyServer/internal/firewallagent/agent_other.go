//go:build !linux

package firewallagent

import (
	"context"
	"errors"
)

func LoadConfig(string) (Config, error) {
	return Config{}, errors.New("firewall-agent 仅支持 Linux 宿主机")
}

func Run(context.Context, Config) error {
	return errors.New("firewall-agent 仅支持 Linux 宿主机")
}
