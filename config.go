package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

const aadSSHScope = "ce6ff14a-7fdc-4685-bbe0-f6afdfcfa8e0/.default"

type Config struct {
	SocketPath       string                      `json:"socket_path,omitempty"`
	RelaySocketPath  string                      `json:"relay_socket_path,omitempty"`
	SubscriptionID   string                      `json:"subscription_id,omitempty"`
	AuthMode         string                      `json:"auth_mode"`
	ServicePrincipal *ServicePrincipalAuthConfig `json:"service_principal,omitempty"`
}

type ServicePrincipalAuthConfig struct {
	TenantID        string `json:"tenant_id"`
	AppID           string `json:"app_id"`
	CredentialType  string `json:"credential_type,omitempty"`
	ClientSecret    string `json:"client_secret,omitempty"`
	KeyVaultURL     string `json:"key_vault_url,omitempty"`
	CertificateName string `json:"certificate_name,omitempty"`
	AuthorityHost   string `json:"authority_host,omitempty"`
}

type oauthTokenResponse struct {
	AccessToken      string `json:"access_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON config: %w", err)
	}

	if strings.TrimSpace(cfg.AuthMode) == "" {
		return nil, errors.New("config.auth_mode is required")
	}

	return &cfg, nil
}
