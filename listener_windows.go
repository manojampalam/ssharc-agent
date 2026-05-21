//go:build windows

package main

import (
	"net"

	"github.com/Microsoft/go-winio"
)

func listenAgentSocket(socketPath string) (net.Listener, error) {
	return winio.ListenPipe(socketPath, nil)
}

func listenRelaySocket(socketPath string) (net.Listener, error) {
	return winio.ListenPipe(socketPath, nil)
}
