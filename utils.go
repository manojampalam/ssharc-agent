package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func generateRSAKeyPair() (*rsa.PrivateKey, ssh.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

func requestToken(tokenURL string, form url.Values) (string, error) {
	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %w", err)
	}

	var tokenResp oauthTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if strings.TrimSpace(tokenResp.ErrorDescription) != "" {
			return "", fmt.Errorf("token request failed (%s): %s", tokenResp.Error, tokenResp.ErrorDescription)
		}
		return "", fmt.Errorf("token request failed with status %d", resp.StatusCode)
	}

	if strings.TrimSpace(tokenResp.AccessToken) == "" {
		return "", errors.New("token response did not include access_token")
	}

	return strings.TrimSpace(tokenResp.AccessToken), nil
}

func newJTI() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return hex.EncodeToString(b)
}

func extractRSAModulusExponent(publicKey ssh.PublicKey) (string, string, error) {
	parts := strings.Fields(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey))))
	if len(parts) < 2 {
		return "", "", errors.New("invalid SSH public key format")
	}
	if parts[0] != "ssh-rsa" {
		return "", "", fmt.Errorf("unsupported key type %q; only ssh-rsa is supported", parts[0])
	}

	keyBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("failed to decode public key payload: %w", err)
	}

	fields, err := readSSHWireFields(keyBytes)
	if err != nil {
		return "", "", err
	}
	if len(fields) < 3 {
		return "", "", fmt.Errorf("invalid RSA key payload: expected 3 fields, got %d", len(fields))
	}

	exponent := base64.URLEncoding.EncodeToString(fields[1])
	modulus := base64.URLEncoding.EncodeToString(fields[2])
	return modulus, exponent, nil
}

func readSSHWireFields(b []byte) ([][]byte, error) {
	var fields [][]byte
	offset := 0
	for offset < len(b) {
		if offset+4 > len(b) {
			return nil, errors.New("invalid SSH wire payload: truncated field length")
		}
		n := int(binary.BigEndian.Uint32(b[offset : offset+4]))
		offset += 4
		if n < 0 || offset+n > len(b) {
			return nil, errors.New("invalid SSH wire payload: field length out of range")
		}
		fields = append(fields, b[offset:offset+n])
		offset += n
	}
	return fields, nil
}

func parseSSHCertificate(certLine string) (*ssh.Certificate, error) {
	return parseSSHCertificateFromBytes([]byte(strings.TrimSpace(certLine) + "\n"))
}

func parseSSHCertificateFromBytes(certBytes []byte) (*ssh.Certificate, error) {
	certKey, _, _, rest, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated SSH certificate: %w", err)
	}
	if len(strings.TrimSpace(string(rest))) > 0 {
		return nil, errors.New("generated certificate contains extra unsupported data")
	}

	cert, ok := certKey.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("generated key is not an SSH certificate")
	}
	return cert, nil
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
