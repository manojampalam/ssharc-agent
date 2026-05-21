package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
)

const armScope = "https://management.azure.com/.default"

func getARMAccessTokenByAuthMode(ctx context.Context, authMode string, cfg *Config) (string, error) {
	switch strings.ToLower(strings.TrimSpace(authMode)) {
	case "az_cli", "az", "azcli":
		return getARMAccessTokenFromAzCLI(ctx)
	case "service_principal", "sp":
		return getARMAccessTokenFromServicePrincipal(ctx, cfg.ServicePrincipal)
	default:
		return "", fmt.Errorf("unsupported auth_mode %q for ARM auth", cfg.AuthMode)
	}
}

func getARMAccessTokenFromAzCLI(ctx context.Context) (string, error) {
	if _, err := exec.LookPath("az"); err != nil {
		return "", fmt.Errorf("az CLI not found in PATH: %w", err)
	}

	args := []string{
		"account", "get-access-token",
		"--resource", "https://management.azure.com/",
		"--query", "accessToken",
		"-o", "tsv",
	}
	cmd := exec.CommandContext(ctx, "az", args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errText := strings.TrimSpace(stderr.String())
		if errText == "" {
			errText = err.Error()
		}
		return "", fmt.Errorf("az account get-access-token failed: %s", errText)
	}

	token := strings.TrimSpace(stdout.String())
	if token == "" {
		return "", fmt.Errorf("az account get-access-token returned empty access token")
	}
	return token, nil
}

func getARMAccessTokenFromServicePrincipal(ctx context.Context, sp *ServicePrincipalAuthConfig) (string, error) {
	if sp == nil {
		return "", fmt.Errorf("service_principal config is required when auth_mode is service_principal")
	}
	if strings.TrimSpace(sp.TenantID) == "" {
		return "", fmt.Errorf("service_principal.tenant_id is required")
	}
	if strings.TrimSpace(sp.AppID) == "" {
		return "", fmt.Errorf("service_principal.app_id is required")
	}

	credentialType := strings.ToLower(strings.TrimSpace(sp.CredentialType))
	if credentialType == "" {
		credentialType = "secret"
	}

	authorityHost := strings.TrimSpace(sp.AuthorityHost)
	if authorityHost == "" {
		authorityHost = "https://login.microsoftonline.com"
	}
	tokenURL := strings.TrimRight(authorityHost, "/") + "/" + strings.TrimSpace(sp.TenantID) + "/oauth2/v2.0/token"

	form := url.Values{}
	form.Set("client_id", strings.TrimSpace(sp.AppID))
	form.Set("grant_type", "client_credentials")
	form.Set("scope", armScope)

	switch credentialType {
	case "secret":
		if strings.TrimSpace(sp.ClientSecret) == "" {
			return "", fmt.Errorf("service_principal.client_secret is required when credential_type is secret")
		}
		form.Set("client_secret", sp.ClientSecret)
	case "keyvault_certificate":
		assertion, err := buildClientAssertionWithKeyVault(ctx, tokenURL, sp)
		if err != nil {
			return "", err
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
	default:
		return "", fmt.Errorf("unsupported service_principal.credential_type %q", sp.CredentialType)
	}

	return requestToken(tokenURL, form)
}

func getSubscriptionIDByAuthMode(ctx context.Context, authMode string, cfg *Config, armToken string) (string, error) {
	override := strings.TrimSpace(cfg.SubscriptionID)
	if override != "" {
		return override, nil
	}

	switch strings.ToLower(strings.TrimSpace(authMode)) {
	case "az_cli", "az", "azcli":
		return getSubscriptionIDFromAzCLI(ctx)
	case "service_principal", "sp":
		return getSubscriptionIDFromARM(ctx, armToken)
	default:
		return "", fmt.Errorf("unsupported auth_mode %q for subscription resolution", cfg.AuthMode)
	}
}

func getSubscriptionIDFromAzCLI(ctx context.Context) (string, error) {
	args := []string{"account", "show", "--query", "id", "-o", "tsv"}
	cmd := exec.CommandContext(ctx, "az", args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errText := strings.TrimSpace(stderr.String())
		if errText == "" {
			errText = err.Error()
		}
		return "", fmt.Errorf("az account show failed: %s", errText)
	}

	subscriptionID := strings.TrimSpace(stdout.String())
	if subscriptionID == "" {
		return "", fmt.Errorf("az account show returned empty subscription id")
	}
	return subscriptionID, nil
}

func getSubscriptionIDFromARM(ctx context.Context, armToken string) (string, error) {
	type subscriptionResponse struct {
		Value []struct {
			SubscriptionID string `json:"subscriptionId"`
			State          string `json:"state"`
		} `json:"value"`
	}

	url := "https://management.azure.com/subscriptions?api-version=2020-01-01"
	body, statusCode, err := doARMRequest(ctx, "GET", url, armToken, nil)
	if err != nil {
		return "", err
	}
	if statusCode != 200 {
		return "", fmt.Errorf("failed to list subscriptions from ARM (status %d): %s", statusCode, strings.TrimSpace(string(body)))
	}

	var resp subscriptionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("failed to decode ARM subscriptions response: %w", err)
	}

	for _, sub := range resp.Value {
		if strings.EqualFold(strings.TrimSpace(sub.State), "Enabled") && strings.TrimSpace(sub.SubscriptionID) != "" {
			return strings.TrimSpace(sub.SubscriptionID), nil
		}
	}
	for _, sub := range resp.Value {
		if strings.TrimSpace(sub.SubscriptionID) != "" {
			return strings.TrimSpace(sub.SubscriptionID), nil
		}
	}

	return "", fmt.Errorf("no subscriptions returned by ARM; set config.subscription_id explicitly")
}
