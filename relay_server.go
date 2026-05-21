package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	relayMsgTypeResponse = "response"
	relayMsgTypeError    = "error"
	relayMaxMessageSize  = 64 * 1024
)

func defaultRelaySocketPath() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\entra-cert-relay`
	}
	return filepath.Join(os.TempDir(), "entra-cert-relay.sock")
}

func serveRelayInfo(ctx context.Context, socketPath string, manager *relayManager) error {
	if manager == nil {
		return fmt.Errorf("relay manager is required")
	}
	if strings.TrimSpace(socketPath) == "" {
		socketPath = defaultRelaySocketPath()
	}

	if runtime.GOOS != "windows" {
		_ = os.Remove(socketPath)
	}

	ln, err := listenRelaySocket(socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on relay socket %q: %w", socketPath, err)
	}
	defer ln.Close()

	if err := os.Setenv("RELAY_INFO_SOCK", socketPath); err != nil {
		log.Printf("warning: failed to set RELAY_INFO_SOCK: %v", err)
	}

	log.Printf("Relay info server listening on %s", socketPath)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("relay accept failed: %w", err)
		}

		go func(c net.Conn) {
			defer c.Close()
			handleRelayClient(ctx, c, manager)
		}(conn)
	}
}

func handleRelayClient(ctx context.Context, conn net.Conn, manager *relayManager) {
	msg, err := readFramedRelayMessage(conn)
	if err != nil {
		sendRelayError(conn, err.Error())
		return
	}

	var req relayInfoRequest
	if err := json.Unmarshal(msg, &req); err != nil {
		sendRelayError(conn, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	if !strings.EqualFold(strings.TrimSpace(req.Command), "get_relay_info") {
		sendRelayError(conn, fmt.Sprintf("unknown command: %s", strings.TrimSpace(req.Command)))
		return
	}

	cred, newServiceConfig, err := manager.getRelayInfo(ctx, req)
	if err != nil {
		sendRelayError(conn, err.Error())
		return
	}

	response := map[string]any{
		"type":               relayMsgTypeResponse,
		"cred":               cred,
		"new_service_config": newServiceConfig,
	}
	if err := writeFramedRelayJSON(conn, response); err != nil {
		log.Printf("relay response write failed: %v", err)
	}
}

func readFramedRelayMessage(conn net.Conn) ([]byte, error) {
	sizeBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, sizeBuf); err != nil {
		return nil, fmt.Errorf("failed to read message size: %w", err)
	}

	size := binary.BigEndian.Uint32(sizeBuf)
	if size == 0 || size > relayMaxMessageSize {
		return nil, fmt.Errorf("message size exceeds maximum")
	}

	msg := make([]byte, size)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, fmt.Errorf("failed to read message body: %w", err)
	}
	return msg, nil
}

func writeFramedRelayJSON(conn net.Conn, response any) error {
	payload, err := json.Marshal(response)
	if err != nil {
		return err
	}

	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if err := writeAll(conn, header); err != nil {
		return err
	}
	return writeAll(conn, payload)
}

func sendRelayError(conn net.Conn, message string) {
	_ = writeFramedRelayJSON(conn, map[string]any{
		"type":  relayMsgTypeError,
		"error": message,
	})
}

func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}
