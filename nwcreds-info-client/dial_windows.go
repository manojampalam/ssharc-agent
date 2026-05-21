//go:build windows

package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

func dialRelaySocket(ctx context.Context, socketPath string) (net.Conn, error) {
	timeout := 30 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		timeout = remaining
	}

	conn, err := winio.DialPipeContext(ctx, socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to relay named pipe %q within %s: %w", socketPath, timeout.Round(time.Millisecond), err)
	}
	return conn, nil
}
