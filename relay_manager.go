package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	relayAPIVersion                 = "2023-03-15"
	relayDefaultEndpointName        = "default"
	relayDefaultServiceName         = "SSH"
	relayMaxValiditySeconds         = 3600
	relayServiceConnectionDelaySecs = 15
)

type relayManager struct {
	cfg   *Config
	mu    sync.Mutex
	cache map[string]relayCacheEntry
}

type relayCacheEntry struct {
	Credential map[string]any
	ExpiresAt  time.Time
}

type relayInfoRequest struct {
	Command      string `json:"command"`
	VMID         string `json:"vm_id"`
	ResourceType string `json:"resource_type,omitempty"`
	Port         int    `json:"port,omitempty"`
}

func newRelayManager(cfg *Config) *relayManager {
	return &relayManager{
		cfg:   cfg,
		cache: make(map[string]relayCacheEntry),
	}
}

func (m *relayManager) getRelayInfo(ctx context.Context, req relayInfoRequest) (map[string]any, error) {
	vmID := strings.TrimSpace(req.VMID)
	if vmID == "" {
		return nil, fmt.Errorf("missing required field: vm_id")
	}

	subscriptionID, resourceGroup, vmName, err := parseVMID(vmID, m.cfg)
	if err != nil {
		return nil, err
	}

	resourceType := strings.TrimSpace(req.ResourceType)
	if resourceType == "" {
		resourceType = "Microsoft.HybridCompute/machines"
	}

	port := req.Port
	if port <= 0 {
		port = 22
	}

	cacheKey := strings.ToLower(resourceGroup + "|" + vmName + "|" + resourceType + "|" + fmt.Sprint(port))
	if cred, ok := m.getCached(cacheKey); ok {
		return cred, nil
	}

	authMode := strings.ToLower(strings.TrimSpace(m.cfg.AuthMode))
	armToken, err := getARMAccessTokenByAuthMode(ctx, authMode, m.cfg)
	if err != nil {
		return nil, err
	}

	if subscriptionID == "" {
		subscriptionID, err = getSubscriptionIDByAuthMode(ctx, authMode, m.cfg, armToken)
		if err != nil {
			return nil, err
		}
	}

	resourceURI, err := buildResourceURI(subscriptionID, resourceGroup, vmName, resourceType)
	if err != nil {
		return nil, err
	}

	cred, err := m.getRelayInfoFromARM(ctx, armToken, resourceURI, port)
	if err != nil {
		return nil, err
	}

	m.storeCached(cacheKey, cred)
	return cred, nil
}

func (m *relayManager) getRelayInfoFromARM(ctx context.Context, armToken, resourceURI string, port int) (map[string]any, error) {
	cred, statusCode, err := listRelayCredentials(ctx, armToken, resourceURI, relayMaxValiditySeconds)
	if err != nil {
		if statusCode == http.StatusNotFound {
			return nil, fmt.Errorf("no relay credentials found; service configuration may need to be created manually")
		} else if statusCode == http.StatusPreconditionFailed {
			return nil, fmt.Errorf("relay service configuration not ready")
		}
		return nil, fmt.Errorf("unable to retrieve relay information: %w", err)
	}

	if cred == nil {
		return nil, fmt.Errorf("no relay credentials available")
	}

	return cred, nil
}

func (m *relayManager) getCached(key string) (map[string]any, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.cache[key]
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.ExpiresAt.Add(-30 * time.Second)) {
		delete(m.cache, key)
		return nil, false
	}
	return entry.Credential, true
}

func (m *relayManager) storeCached(key string, credential map[string]any) {
	expiresAt := parseRelayExpiresOn(credential)
	if expiresAt.IsZero() {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache[key] = relayCacheEntry{Credential: credential, ExpiresAt: expiresAt}
}

func parseRelayExpiresOn(credential map[string]any) time.Time {
	value, ok := credential["expiresOn"]
	if !ok {
		return time.Time{}
	}
	switch v := value.(type) {
	case float64:
		return time.Unix(int64(v), 0)
	case int64:
		return time.Unix(v, 0)
	case int:
		return time.Unix(int64(v), 0)
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return time.Time{}
		}
		return time.Unix(n, 0)
	case string:
		if strings.TrimSpace(v) == "" {
			return time.Time{}
		}
		var n json.Number = json.Number(v)
		ni, err := n.Int64()
		if err != nil {
			return time.Time{}
		}
		return time.Unix(ni, 0)
	default:
		return time.Time{}
	}
}

func parseVMID(vmID string, cfg *Config) (subscriptionID, resourceGroup, vmName string, err error) {
	parts := strings.Split(strings.TrimSpace(vmID), ".")
	if len(parts) < 2 || len(parts) > 3 {
		return "", "", "", fmt.Errorf("invalid vm_id format: expected [subscription-id.]resource-group.vm-name")
	}

	if len(parts) == 3 {
		subscriptionID = strings.TrimSpace(parts[0])
		resourceGroup = strings.TrimSpace(parts[1])
		vmName = strings.TrimSpace(parts[2])
	} else {
		resourceGroup = strings.TrimSpace(parts[0])
		vmName = strings.TrimSpace(parts[1])
		// subscriptionID will be empty and will be resolved later
	}

	if resourceGroup == "" || vmName == "" {
		return "", "", "", fmt.Errorf("invalid vm_id: resource-group and vm-name cannot be empty")
	}

	return subscriptionID, resourceGroup, vmName, nil
}

func buildResourceURI(subscriptionID, resourceGroup, vmName, resourceType string) (string, error) {
	subscriptionID = strings.TrimSpace(subscriptionID)
	resourceGroup = strings.TrimSpace(resourceGroup)
	vmName = strings.TrimSpace(vmName)
	resourceType = strings.TrimSpace(resourceType)

	if subscriptionID == "" || resourceGroup == "" || vmName == "" || resourceType == "" {
		return "", fmt.Errorf("subscription id, resource_group, vm_name, and resource_type are required")
	}
	parts := strings.SplitN(resourceType, "/", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", fmt.Errorf("invalid resource_type %q; expected <namespace>/<type>", resourceType)
	}

	return fmt.Sprintf(
		"/subscriptions/%s/resourceGroups/%s/providers/%s/%s/%s",
		subscriptionID,
		resourceGroup,
		parts[0],
		parts[1],
		vmName,
	), nil
}

func listRelayCredentials(ctx context.Context, armToken, resourceURI string, expiresIn int) (map[string]any, int, error) {
	url := fmt.Sprintf(
		"https://management.azure.com%s/providers/Microsoft.HybridConnectivity/endpoints/%s/listCredentials?expiresin=%d&api-version=%s",
		resourceURI,
		relayDefaultEndpointName,
		expiresIn,
		relayAPIVersion,
	)

	payload := map[string]string{"serviceName": relayDefaultServiceName}
	body, statusCode, err := doARMRequest(ctx, http.MethodPost, url, armToken, payload)
	if err != nil {
		return nil, statusCode, err
	}

	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, statusCode, fmt.Errorf("failed to decode listCredentials response: %w", err)
	}

	if relay, ok := parsed["relay"].(map[string]any); ok {
		return relay, statusCode, nil
	}
	return parsed, statusCode, nil
}

func createDefaultEndpoint(ctx context.Context, armToken, resourceURI string) error {
	url := fmt.Sprintf(
		"https://management.azure.com%s/providers/Microsoft.HybridConnectivity/endpoints/%s?api-version=%s",
		resourceURI,
		relayDefaultEndpointName,
		relayAPIVersion,
	)

	payload := map[string]any{
		"properties": map[string]any{"type": "default"},
	}
	_, statusCode, err := doARMRequest(ctx, http.MethodPut, url, armToken, payload)
	if err != nil {
		return fmt.Errorf("failed to create default endpoint (status %d): %w", statusCode, err)
	}
	return nil
}

func checkServiceConfiguration(ctx context.Context, armToken, resourceURI string, port int) (bool, error) {
	url := fmt.Sprintf(
		"https://management.azure.com%s/providers/Microsoft.HybridConnectivity/endpoints/%s/serviceConfigurations/%s?api-version=%s",
		resourceURI,
		relayDefaultEndpointName,
		relayDefaultServiceName,
		relayAPIVersion,
	)

	body, statusCode, err := doARMRequest(ctx, http.MethodGet, url, armToken, nil)
	if err != nil {
		if statusCode == http.StatusForbidden || statusCode == http.StatusUnauthorized {
			return true, nil
		}
		if statusCode == http.StatusNotFound {
			return false, nil
		}
		return false, fmt.Errorf("failed to get service configuration: %w", err)
	}

	var parsed struct {
		Properties struct {
			Port int `json:"port"`
		} `json:"properties"`
		Port int `json:"port"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false, fmt.Errorf("failed to decode service configuration response: %w", err)
	}

	configuredPort := parsed.Properties.Port
	if configuredPort == 0 {
		configuredPort = parsed.Port
	}
	if configuredPort == 0 {
		return false, nil
	}

	if port > 0 {
		return configuredPort == port, nil
	}
	return true, nil
}

func createServiceConfiguration(ctx context.Context, armToken, resourceURI string, port int) error {
	if port <= 0 {
		port = 22
	}

	url := fmt.Sprintf(
		"https://management.azure.com%s/providers/Microsoft.HybridConnectivity/endpoints/%s/serviceConfigurations/%s?api-version=%s",
		resourceURI,
		relayDefaultEndpointName,
		relayDefaultServiceName,
		relayAPIVersion,
	)

	payload := map[string]any{
		"properties": map[string]any{
			"serviceName": relayDefaultServiceName,
			"port":        port,
		},
	}

	_, statusCode, err := doARMRequest(ctx, http.MethodPut, url, armToken, payload)
	if err != nil {
		return fmt.Errorf("failed to create service configuration (status %d): %w", statusCode, err)
	}
	return nil
}

func waitRelayConnectionDelay(ctx context.Context) {
	timer := time.NewTimer(relayServiceConnectionDelaySecs * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func doARMRequest(ctx context.Context, method, endpoint, armToken string, payload any) ([]byte, int, error) {
	var bodyReader *bytes.Reader
	if payload == nil {
		bodyReader = bytes.NewReader(nil)
	} else {
		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to encode ARM request payload: %w", err)
		}
		bodyReader = bytes.NewReader(payloadBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create ARM request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(armToken))
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("ARM request failed: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read ARM response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return responseBody, resp.StatusCode, fmt.Errorf("ARM request failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	return responseBody, resp.StatusCode, nil
}
