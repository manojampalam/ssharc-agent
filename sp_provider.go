package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/crypto/ssh"
)

func getSSHCertificateFromServicePrincipal(publicKey ssh.PublicKey, sp *ServicePrincipalAuthConfig) (*ssh.Certificate, error) {
	if sp == nil {
		return nil, errors.New("service_principal config is required when auth_mode is service_principal")
	}
	if strings.TrimSpace(sp.TenantID) == "" {
		return nil, errors.New("service_principal.tenant_id is required")
	}
	if strings.TrimSpace(sp.AppID) == "" {
		return nil, errors.New("service_principal.app_id is required")
	}

	credentialType := strings.ToLower(strings.TrimSpace(sp.CredentialType))
	if credentialType == "" {
		credentialType = "secret"
	}
	if credentialType != "secret" && credentialType != "keyvault_certificate" {
		return nil, fmt.Errorf("unsupported service_principal.credential_type %q", sp.CredentialType)
	}
	if credentialType == "secret" && strings.TrimSpace(sp.ClientSecret) == "" {
		return nil, errors.New("service_principal.client_secret is required when credential_type is secret")
	}
	if credentialType == "keyvault_certificate" {
		if strings.TrimSpace(sp.KeyVaultURL) == "" {
			return nil, errors.New("service_principal.key_vault_url is required when credential_type is keyvault_certificate")
		}
		if strings.TrimSpace(sp.CertificateName) == "" {
			return nil, errors.New("service_principal.certificate_name is required when credential_type is keyvault_certificate")
		}
	}

	modulus, exponent, err := extractRSAModulusExponent(publicKey)
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	h.Write([]byte(modulus))
	h.Write([]byte(exponent))
	keyID := hex.EncodeToString(h.Sum(nil))

	jwk := map[string]string{
		"kty": "RSA",
		"n":   modulus,
		"e":   exponent,
		"kid": keyID,
	}
	reqCNF, err := json.Marshal(jwk)
	if err != nil {
		return nil, fmt.Errorf("failed to encode JWK: %w", err)
	}

	authorityHost := strings.TrimSpace(sp.AuthorityHost)
	if authorityHost == "" {
		authorityHost = "https://login.microsoftonline.com"
	}
	tokenURL := strings.TrimRight(authorityHost, "/") + "/" + strings.TrimSpace(sp.TenantID) + "/oauth2/v2.0/token"

	form := url.Values{}
	form.Set("client_id", strings.TrimSpace(sp.AppID))
	form.Set("grant_type", "client_credentials")
	form.Set("scope", aadSSHScope)
	form.Set("token_type", "ssh-cert")
	form.Set("req_cnf", string(reqCNF))
	form.Set("key_id", keyID)

	if credentialType == "secret" {
		form.Set("client_secret", sp.ClientSecret)
	} else {
		assertion, err := buildClientAssertionWithKeyVault(context.Background(), tokenURL, sp)
		if err != nil {
			return nil, err
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
	}

	accessToken, err := requestToken(tokenURL, form)
	if err != nil {
		return nil, err
	}

	certLine := "ssh-rsa-cert-v01@openssh.com " + accessToken
	return parseSSHCertificate(certLine)
}
