package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

func buildClientAssertionWithKeyVault(ctx context.Context, tokenURL string, sp *ServicePrincipalAuthConfig) (string, error) {
	vaultToken, err := getManagedIdentityTokenForKeyVault(ctx)
	if err != nil {
		return "", err
	}
	authHeader := "Bearer " + vaultToken

	x5t, keyKID, err := getCertificateMetadata(ctx, strings.TrimSpace(sp.KeyVaultURL), strings.TrimSpace(sp.CertificateName), authHeader)
	if err != nil {
		return "", err
	}

	now := time.Now().Unix()
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
	}
	if x5t != "" {
		header["x5t"] = x5t
	}

	claims := map[string]any{
		"aud": tokenURL,
		"iss": strings.TrimSpace(sp.AppID),
		"sub": strings.TrimSpace(sp.AppID),
		"jti": newJTI(),
		"nbf": now - 60,
		"exp": now + 600,
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	unsignedJWT := encodedHeader + "." + encodedClaims

	digest := sha256.Sum256([]byte(unsignedJWT))
	signature, err := signDigestWithKeyVault(ctx, keyKID, digest[:], authHeader)
	if err != nil {
		return "", err
	}

	return unsignedJWT + "." + signature, nil
}

func getManagedIdentityTokenForKeyVault(ctx context.Context) (string, error) {
	cred, err := azidentity.NewManagedIdentityCredential(nil)
	if err != nil {
		return "", fmt.Errorf("failed to create managed identity credential: %w", err)
	}

	tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{"https://vault.azure.net/.default"}})
	if err != nil {
		return "", fmt.Errorf("failed to get managed identity token for Key Vault: %w", err)
	}

	if strings.TrimSpace(tok.Token) == "" {
		return "", errors.New("managed identity token for Key Vault is empty")
	}

	return tok.Token, nil
}

func getCertificateMetadata(ctx context.Context, keyVaultURL, certificateName, authHeader string) (x5t string, keyKID string, err error) {
	vault := strings.TrimRight(strings.TrimSpace(keyVaultURL), "/")
	if vault == "" {
		return "", "", errors.New("key_vault_url is empty")
	}
	if strings.TrimSpace(certificateName) == "" {
		return "", "", errors.New("certificate_name is empty")
	}

	endpoint := vault + "/certificates/" + url.PathEscape(certificateName) + "?api-version=7.4"
	body, statusCode, err := doKeyVaultRequest(ctx, http.MethodGet, endpoint, nil, authHeader)
	if err != nil {
		return "", "", err
	}
	if statusCode != http.StatusOK {
		return "", "", fmt.Errorf("failed to read certificate metadata from Key Vault (status %d)", statusCode)
	}

	var response struct {
		X5t string `json:"x5t"`
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", "", fmt.Errorf("failed to decode certificate metadata response: %w", err)
	}
	if strings.TrimSpace(response.X5t) == "" {
		return "", "", errors.New("key vault certificate metadata did not include x5t")
	}
	if strings.TrimSpace(response.KID) == "" {
		return "", "", errors.New("key vault certificate metadata did not include kid")
	}

	return strings.TrimSpace(response.X5t), strings.TrimSpace(response.KID), nil
}

func signDigestWithKeyVault(ctx context.Context, keyKID string, digest []byte, authHeader string) (string, error) {
	if strings.TrimSpace(keyKID) == "" {
		return "", errors.New("key id is empty")
	}

	signURL := strings.TrimRight(keyKID, "/") + "/sign?api-version=7.4"
	payload := map[string]string{
		"alg":   "RS256",
		"value": base64.RawURLEncoding.EncodeToString(digest),
	}
	body, statusCode, err := doKeyVaultRequest(ctx, http.MethodPost, signURL, payload, authHeader)
	if err != nil {
		return "", err
	}
	if statusCode != http.StatusOK {
		return "", fmt.Errorf("key vault sign operation failed with status %d", statusCode)
	}

	var response struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to decode key vault sign response: %w", err)
	}
	if strings.TrimSpace(response.Value) == "" {
		return "", errors.New("key vault sign response did not include signature value")
	}

	return strings.TrimSpace(response.Value), nil
}

func doKeyVaultRequest(ctx context.Context, method, endpoint string, payload any, authHeader string) ([]byte, int, error) {
	var body io.Reader
	if payload != nil {
		jsonPayload, err := json.Marshal(payload)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to encode Key Vault request payload: %w", err)
		}
		body = bytes.NewReader(jsonPayload)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create Key Vault request: %w", err)
	}
	req.Header.Set("Authorization", authHeader)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("Key Vault request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read Key Vault response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return respBody, resp.StatusCode, fmt.Errorf("Key Vault request failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	return respBody, resp.StatusCode, nil
}
