package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
)

var version = "dev"

func main() {
	var configPath string
	var showVersion bool
	flag.StringVar(&configPath, "config", "config.json", "Path to JSON config file")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Fprintf(os.Stdout, "ssharc-agent version %s\n", strings.TrimSpace(version))
		return
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		die("failed to load config: %v", err)
	}

	privateKey, publicKey, err := generateRSAKeyPair()
	if err != nil {
		die("failed to generate RSA keypair: %v", err)
	}

	cert, err := getSSHCertificateByAuthMode(strings.ToLower(strings.TrimSpace(cfg.AuthMode)), publicKey, cfg)
	if err != nil {
		die("failed to get certificate: %v", err)
	}
	renew := func() (*ssh.Certificate, error) {
		return getSSHCertificateByAuthMode(strings.ToLower(strings.TrimSpace(cfg.AuthMode)), publicKey, cfg)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	socketPath := strings.TrimSpace(cfg.SocketPath)
	if socketPath == "" {
		socketPath = defaultSocketPath()
	}
	relaySocketPath := strings.TrimSpace(cfg.RelaySocketPath)
	if relaySocketPath == "" {
		relaySocketPath = defaultRelaySocketPath()
	}

	relayMgr := newRelayManager(cfg)
	relayErrCh := make(chan error, 1)
	go func() {
		err := serveRelayInfo(ctx, relaySocketPath, relayMgr)
		relayErrCh <- err
		if err != nil {
			stop()
		}
	}()

	if err := serveSSHAgent(ctx, socketPath, privateKey, cert, renew); err != nil {
		stop()
		relayErr := <-relayErrCh
		if relayErr != nil {
			log.Printf("relay server stopped with error: %v", relayErr)
		}
		die("failed to run SSH agent: %v", err)
	}

	stop()
	relayErr := <-relayErrCh
	if relayErr != nil {
		die("relay info server failed: %v", relayErr)
	}

	log.Printf("SSH agent stopped")
}

func getSSHCertificateByAuthMode(authMode string, publicKey ssh.PublicKey, cfg *Config) (*ssh.Certificate, error) {
	switch authMode {
	case "az_cli", "az", "azcli":
		return getSSHCertificateFromAzCLI(publicKey)
	case "service_principal", "sp":
		return getSSHCertificateFromServicePrincipal(publicKey, cfg.ServicePrincipal)
	default:
		return nil, fmt.Errorf("unsupported auth_mode %q (expected az_cli or service_principal)", cfg.AuthMode)
	}
}
