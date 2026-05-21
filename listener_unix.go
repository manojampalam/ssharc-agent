//go:build !windows

package main

import "net"

func listenAgentSocket(socketPath string) (net.Listener, error) {
	return net.Listen("unix", socketPath)
}

func listenRelaySocket(socketPath string) (net.Listener, error) {
	return net.Listen("unix", socketPath)
}
