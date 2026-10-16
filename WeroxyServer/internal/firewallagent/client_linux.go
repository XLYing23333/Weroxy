//go:build linux

package firewallagent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"
)

// Submit sends one bounded, structured request over the protected local socket.
func Submit(parent context.Context, request Request) (Response, error) {
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", SocketPath)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return Response{}, err
	}
	var response Response
	if err := json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&response); err != nil {
		return Response{}, err
	}
	if response.Status == "" {
		return Response{}, errors.New("empty agent response")
	}
	return response, nil
}

// Query obtains only the agent's latest self-reported state. It does not
// claim that a host rule still exists after outside firewall changes.
func Query(parent context.Context) (Response, error) {
	response, err := Submit(parent, Request{Operation: "query"})
	if err != nil {
		return Response{}, err
	}
	if response.Status != "ok" {
		return Response{}, errors.New("agent query rejected")
	}
	return response, nil
}
