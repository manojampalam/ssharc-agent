package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func defaultSocketPath() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\entra-cert-agent`
	}
	return filepath.Join(os.TempDir(), "entra-cert-agent.sock")
}

func serveSSHAgent(
	ctx context.Context,
	socketPath string,
	privateKey *rsa.PrivateKey,
	cert *ssh.Certificate,
	renewCert func() (*ssh.Certificate, error),
) error {
	const refreshInterval = 60 * time.Second
	const refreshThreshold = 5 * time.Minute

	if strings.TrimSpace(socketPath) == "" {
		socketPath = defaultSocketPath()
	}

	if runtime.GOOS != "windows" {
		_ = os.Remove(socketPath)
	}

	ln, err := listenAgentSocket(socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on agent socket %q: %w", socketPath, err)
	}
	defer ln.Close()

	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{
		PrivateKey:   privateKey,
		Certificate:  cert,
		Comment:      "entra-cert",
		LifetimeSecs: 0,
	}); err != nil {
		return fmt.Errorf("failed to add key identity to agent: %w", err)
	}

	if renewCert != nil {
		go func() {
			ticker := time.NewTicker(refreshInterval)
			defer ticker.Stop()

			currentCert := cert
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					remaining := timeToCertExpiry(currentCert)
					if remaining > refreshThreshold {
						continue
					}

					newCert, err := renewCert()
					if err != nil {
						log.Printf("certificate refresh failed: %v", err)
						continue
					}

					if err := keyring.RemoveAll(); err != nil {
						log.Printf("certificate refresh failed to clear keyring: %v", err)
						continue
					}
					if err := keyring.Add(agent.AddedKey{
						PrivateKey:   privateKey,
						Certificate:  newCert,
						Comment:      "entra-cert",
						LifetimeSecs: 0,
					}); err != nil {
						log.Printf("certificate refresh failed to add new identity: %v", err)
						continue
					}

					currentCert = newCert
					log.Printf("certificate refreshed; next expiry in %s", timeToCertExpiry(currentCert).Round(time.Second))
				}
			}
		}()
	}

	log.Printf("SSH agent listening on %s", socketPath)

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
			return fmt.Errorf("agent accept failed: %w", err)
		}

		go func(c net.Conn) {
			defer c.Close()
			if err := agent.ServeAgent(keyring, c); err != nil {
				log.Printf("agent session error: %v", err)
			}
		}(conn)
	}
}

func timeToCertExpiry(cert *ssh.Certificate) time.Duration {
	if cert == nil {
		return 0
	}
	if cert.ValidBefore == 0 || cert.ValidBefore == ^uint64(0) {
		return 100 * 365 * 24 * time.Hour
	}
	expiresAt := time.Unix(int64(cert.ValidBefore), 0)
	return time.Until(expiresAt)
}
