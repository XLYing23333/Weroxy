package upgrade

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"time"
)

// A verified candidate can still behave incorrectly; cap subprocess output and
// waiting on inherited pipes as well as its existing execution deadline.
func candidateVersion(ctx context.Context, path string) ([]byte, error) {
	output := &versionOutput{}
	cmd := exec.CommandContext(ctx, path, "version")
	cmd.Stdout = output
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if output.exceeded {
		return nil, errors.New("candidate version output exceeds budget")
	}
	return output.body, err
}

type versionOutput struct {
	body     []byte
	exceeded bool
}

func (out *versionOutput) Write(value []byte) (int, error) {
	const limit = 4096
	if len(value) > limit-len(out.body) {
		out.exceeded = true
		return 0, io.ErrShortBuffer
	}
	out.body = append(out.body, value...)
	return len(value), nil
}
