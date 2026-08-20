package warp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultAPIURL        = "https://api.cloudflareclient.com"
	DefaultAPIVersion    = "v0a4471"
	defaultUserAgent     = "WARP for Android"
	defaultClientVersion = "a-6.35-4471"
	defaultDeviceModel   = "PC"
	defaultDeviceLocale  = "en_US"
	maxAPIResponseSize   = 4 << 20

	KeyTypeWireGuard = "curve25519"
	KeyTypeMASQUE    = "secp256r1"
	TunnelWireGuard  = "wireguard"
	TunnelMASQUE     = "masque"
)

// APIClient implements the small, unofficial device-registration API surface
// used by the Cloudflare WARP clients. Cloudflare doesn't publish this API, so
// its wire format is intentionally isolated from the standards-based MASQUE
// implementation.
type APIClient struct {
	HTTPClient *http.Client
	BaseURL    string
	APIVersion string
}

type Registration struct {
	Key          string `json:"key"`
	InstallID    string `json:"install_id"`
	FCMToken     string `json:"fcm_token"`
	TOS          string `json:"tos"`
	Model        string `json:"model"`
	SerialNumber string `json:"serial_number"`
	OSVersion    string `json:"os_version"`
	KeyType      string `json:"key_type"`
	TunnelType   string `json:"tunnel_type"`
	Locale       string `json:"locale"`
	Type         string `json:"type"`
}

type DeviceUpdate struct {
	Key        string `json:"key"`
	KeyType    string `json:"key_type"`
	TunnelType string `json:"tunnel_type"`
	Name       string `json:"name,omitempty"`
}

type Device struct {
	ID         string       `json:"id"`
	Token      string       `json:"token,omitempty"`
	Key        string       `json:"key,omitempty"`
	KeyType    string       `json:"key_type,omitempty"`
	TunnelType string       `json:"tunnel_type,omitempty"`
	Config     DeviceConfig `json:"config"`
}

type DeviceConfig struct {
	ClientID  string          `json:"client_id,omitempty"`
	Interface DeviceInterface `json:"interface"`
	Peers     []DevicePeer    `json:"peers"`
}

type DeviceInterface struct {
	Addresses DeviceAddresses `json:"addresses"`
}

type DeviceAddresses struct {
	V4 string `json:"v4"`
	V6 string `json:"v6"`
}

type DevicePeer struct {
	PublicKey string         `json:"public_key"`
	Endpoint  DeviceEndpoint `json:"endpoint"`
}

type DeviceEndpoint struct {
	Host  string `json:"host"`
	V4    string `json:"v4"`
	V6    string `json:"v6"`
	Ports []int  `json:"ports,omitempty"`
}

type APIError struct {
	StatusCode int
	Errors     []APIErrorDetail `json:"errors"`
	Message    string           `json:"message,omitempty"`
}

type APIErrorDetail struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *APIError) Error() string {
	messages := make([]string, 0, len(e.Errors)+1)
	if e.Message != "" {
		messages = append(messages, e.Message)
	}
	for _, detail := range e.Errors {
		if detail.Code != 0 {
			messages = append(messages, fmt.Sprintf("%d: %s", detail.Code, detail.Message))
		} else if detail.Message != "" {
			messages = append(messages, detail.Message)
		}
	}
	if len(messages) == 0 {
		return fmt.Sprintf("warp API returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("warp API returned HTTP %d: %s", e.StatusCode, strings.Join(messages, "; "))
}

func NewAPIClient(httpClient *http.Client) *APIClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &APIClient{
		HTTPClient: httpClient,
		BaseURL:    DefaultAPIURL,
		APIVersion: DefaultAPIVersion,
	}
}

// RegisterDevice creates a consumer WARP registration. As in wgcf and usque,
// the initial registration uses a WireGuard public key; callers can then enroll
// a MASQUE key with EnrollDevice.
func (c *APIClient) RegisterDevice(ctx context.Context, publicKey string) (*Device, error) {
	if publicKey == "" {
		return nil, errors.New("warp: registration public key is required")
	}
	serial := make([]byte, 8)
	if _, err := rand.Read(serial); err != nil {
		return nil, fmt.Errorf("warp: generate device serial: %w", err)
	}
	request := Registration{
		Key:          publicKey,
		InstallID:    "",
		FCMToken:     "",
		TOS:          time.Now().Format("2006-01-02T15:04:05.000-07:00"),
		Model:        defaultDeviceModel,
		SerialNumber: hex.EncodeToString(serial),
		OSVersion:    "",
		KeyType:      KeyTypeWireGuard,
		TunnelType:   TunnelWireGuard,
		Locale:       defaultDeviceLocale,
		Type:         "Android",
	}
	var device Device
	if err := c.doJSON(ctx, http.MethodPost, c.endpoint("reg"), "", request, &device); err != nil {
		return nil, err
	}
	return &device, nil
}

// EnrollDevice replaces a registered device key and selects its tunnel
// protocol.
func (c *APIClient) EnrollDevice(ctx context.Context, deviceID, accessToken, publicKey, keyType, tunnelType, name string) (*Device, error) {
	if deviceID == "" || accessToken == "" {
		return nil, errors.New("warp: device ID and access token are required")
	}
	if publicKey == "" {
		return nil, errors.New("warp: enrollment public key is required")
	}
	if (keyType != KeyTypeWireGuard || tunnelType != TunnelWireGuard) && (keyType != KeyTypeMASQUE || tunnelType != TunnelMASQUE) {
		return nil, fmt.Errorf("warp: unsupported enrollment key type %q and tunnel type %q", keyType, tunnelType)
	}
	request := DeviceUpdate{Key: publicKey, KeyType: keyType, TunnelType: tunnelType, Name: name}
	var device Device
	if err := c.doJSON(ctx, http.MethodPatch, c.endpoint("reg", deviceID), accessToken, request, &device); err != nil {
		return nil, err
	}
	return &device, nil
}

func (c *APIClient) GetDevice(ctx context.Context, deviceID, accessToken string) (*Device, error) {
	if deviceID == "" || accessToken == "" {
		return nil, errors.New("warp: device ID and access token are required")
	}
	var device Device
	if err := c.doJSON(ctx, http.MethodGet, c.endpoint("reg", deviceID), accessToken, nil, &device); err != nil {
		return nil, err
	}
	return &device, nil
}

func (c *APIClient) endpoint(parts ...string) string {
	base := strings.TrimRight(c.BaseURL, "/")
	version := strings.Trim(c.APIVersion, "/")
	escaped := make([]string, len(parts))
	for index, part := range parts {
		escaped[index] = url.PathEscape(part)
	}
	return base + "/" + version + "/" + strings.Join(escaped, "/")
}

func (c *APIClient) doJSON(ctx context.Context, method, endpoint, bearer string, body any, result any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("warp: encode API request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return fmt.Errorf("warp: create API request: %w", err)
	}
	request.Header.Set("User-Agent", defaultUserAgent)
	request.Header.Set("CF-Client-Version", defaultClientVersion)
	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	request.Header.Set("Connection", "Keep-Alive")
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := c.HTTPClient.Do(request)
	if err != nil {
		return fmt.Errorf("warp: API request: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxAPIResponseSize+1))
	if err != nil {
		return fmt.Errorf("warp: read API response: %w", err)
	}
	if len(responseBody) > maxAPIResponseSize {
		return errors.New("warp: API response exceeds size limit")
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		apiError := &APIError{StatusCode: response.StatusCode}
		_ = json.Unmarshal(responseBody, apiError)
		return apiError
	}
	if result == nil || len(responseBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(responseBody, result); err != nil {
		return fmt.Errorf("warp: decode API response: %w", err)
	}
	return nil
}
