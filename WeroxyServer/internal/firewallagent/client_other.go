//go:build !linux

package firewallagent

import (
	"context"
	"errors"
)

func Query(context.Context) (Response, error) {
	return Response{}, errors.New("firewall-agent 仅支持 Linux 宿主机")
}

func Submit(context.Context, Request) (Response, error) {
	return Response{}, errors.New("firewall-agent 仅支持 Linux 宿主机")
}
