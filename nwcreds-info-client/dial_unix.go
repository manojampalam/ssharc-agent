//go:build !windows

package main

import (
	"context"
	"fmt"
	"net"
)

func dialRelaySocket(ctx context.Context, socketPath string) (net.Conn, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to relay unix socket %q: %w", socketPath, err)
	}
	return conn, nil
}
