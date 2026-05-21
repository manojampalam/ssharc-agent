package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

func getSSHCertificateFromAzCLI(publicKey ssh.PublicKey) (*ssh.Certificate, error) {
	if _, err := exec.LookPath("az"); err != nil {
		return nil, fmt.Errorf("az CLI not found in PATH: %w", err)
	}

	tempDir, err := os.MkdirTemp("", "entra-cert-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	tempPubPath := filepath.Join(tempDir, "id_rsa.pub")
	tempOutPath := filepath.Join(tempDir, "ssh-cert.pub")
	if err := os.WriteFile(tempPubPath, ssh.MarshalAuthorizedKey(publicKey), 0o644); err != nil {
		return nil, fmt.Errorf("failed to create temp public key file: %w", err)
	}

	args := []string{
		"ssh", "cert",
		"--public-key-file", tempPubPath,
		"--file", tempOutPath,
		"--output", "none",
	}

	cmd := exec.Command("az", args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errText := strings.TrimSpace(stderr.String())
		if errText == "" {
			errText = strings.TrimSpace(stdout.String())
		}
		if errText == "" {
			errText = err.Error()
		}
		return nil, fmt.Errorf("az ssh cert failed: %s", errText)
	}

	certBytes, err := os.ReadFile(tempOutPath)
	if err != nil {
		return nil, fmt.Errorf("certificate file was not created at %q: %w", tempOutPath, err)
	}

	return parseSSHCertificateFromBytes(certBytes)
}
