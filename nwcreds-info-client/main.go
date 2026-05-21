package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const maxRelayMessageSize = 64 * 1024

type relayRequest struct {
	Command      string `json:"command"`
	VMID         string `json:"vm_id"`
	ResourceType string `json:"resource_type,omitempty"`
	Port         int    `json:"port,omitempty"`
}

type relayResponse struct {
	Type  string         `json:"type"`
	Error string         `json:"error,omitempty"`
	Cred  map[string]any `json:"cred,omitempty"`
}

func main() {
	vmID := flag.String("vm-id", "", "VM ID in format [subscription-id.]resource-group.vm-name")
	resourceType := flag.String("resource-type", "Microsoft.HybridCompute/machines", "ARM resource type")
	port := flag.Int("port", 22, "SSH port to request")
	socketPath := flag.String("socket-path", "", "Relay socket path or named pipe")
	timeout := flag.Duration("timeout", 30*time.Second, "Request timeout")
	pretty := flag.Bool("pretty", true, "Pretty-print JSON output")
	flag.Parse()

	if strings.TrimSpace(*vmID) == "" {
		die("--vm-id is required (format: [subscription-id.]resource-group.vm-name)")
	}

	path := strings.TrimSpace(*socketPath)
	if path == "" {
		path = strings.TrimSpace(os.Getenv("RELAY_INFO_SOCK"))
	}
	if path == "" {
		path = defaultRelaySocketPath()
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	resp, err := getRelayInfo(ctx, path, relayRequest{
		Command:      "get_nw_creds",
		VMID:         strings.TrimSpace(*vmID),
		ResourceType: strings.TrimSpace(*resourceType),
		Port:         *port,
	})
	if err != nil {
		die("relay request failed: %v", err)
	}

	if strings.EqualFold(strings.TrimSpace(resp.Type), "error") {
		die("relay server returned error: %s", strings.TrimSpace(resp.Error))
	}

	if *pretty {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
		return
	}

	b, _ := json.Marshal(resp)
	_, _ = fmt.Fprintln(os.Stdout, string(b))
}

func getRelayInfo(ctx context.Context, socketPath string, request relayRequest) (*relayResponse, error) {
	conn, err := dialRelaySocket(ctx, socketPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	payload, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	if len(payload) > maxRelayMessageSize {
		return nil, fmt.Errorf("request too large: %d bytes", len(payload))
	}

	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if err := writeAll(conn, header); err != nil {
		return nil, fmt.Errorf("failed to send request size: %w", err)
	}
	if err := writeAll(conn, payload); err != nil {
		return nil, fmt.Errorf("failed to send request body: %w", err)
	}

	sizeBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, sizeBuf); err != nil {
		return nil, fmt.Errorf("failed to read response size: %w", err)
	}
	responseSize := binary.BigEndian.Uint32(sizeBuf)
	if responseSize == 0 || responseSize > maxRelayMessageSize {
		return nil, fmt.Errorf("invalid response size: %d", responseSize)
	}

	responseBytes := make([]byte, responseSize)
	if _, err := io.ReadFull(conn, responseBytes); err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var response relayResponse
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response JSON: %w", err)
	}
	return &response, nil
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

func defaultRelaySocketPath() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\ssharc-agent-nw`
	}
	return filepath.Join(os.TempDir(), "ssharc-agent-nw.sock")
}

func die(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
