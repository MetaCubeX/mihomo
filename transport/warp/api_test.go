package warp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRegisterDevice(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/test/reg", r.URL.EscapedPath())
		require.Empty(t, r.Header.Get("Authorization"))
		require.Equal(t, defaultUserAgent, r.Header.Get("User-Agent"))
		require.Equal(t, defaultClientVersion, r.Header.Get("CF-Client-Version"))

		var registration Registration
		require.NoError(t, json.NewDecoder(r.Body).Decode(&registration))
		require.Equal(t, "public-key", registration.Key)
		require.Equal(t, KeyTypeWireGuard, registration.KeyType)
		require.Equal(t, TunnelWireGuard, registration.TunnelType)
		require.Equal(t, defaultDeviceModel, registration.Model)
		require.Equal(t, defaultDeviceLocale, registration.Locale)
		require.Equal(t, "Android", registration.Type)
		require.Len(t, registration.SerialNumber, 16)
		_, err := time.Parse("2006-01-02T15:04:05.000-07:00", registration.TOS)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"device-id","token":"access-token"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.Client())
	client.BaseURL = server.URL
	client.APIVersion = "test"
	device, err := client.RegisterDevice(context.Background(), "public-key")
	require.NoError(t, err)
	require.Equal(t, "device-id", device.ID)
	require.Equal(t, "access-token", device.Token)
}

func TestEnrollDevice(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPatch, r.Method)
		require.Equal(t, "/test/reg/device-id", r.URL.EscapedPath())
		require.Equal(t, "Bearer access-token", r.Header.Get("Authorization"))
		require.Equal(t, defaultUserAgent, r.Header.Get("User-Agent"))
		require.Equal(t, defaultClientVersion, r.Header.Get("CF-Client-Version"))

		var update DeviceUpdate
		require.NoError(t, json.NewDecoder(r.Body).Decode(&update))
		require.Equal(t, DeviceUpdate{
			Key:        "public-key",
			KeyType:    KeyTypeMASQUE,
			TunnelType: TunnelMASQUE,
			Name:       "laptop",
		}, update)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "id":"device-id",
  "key_type":"secp256r1",
  "tunnel_type":"masque",
  "config":{
    "interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700::2"}},
    "peers":[{"public_key":"peer-key","endpoint":{"host":"engage.example:2408","v4":"192.0.2.1:0","v6":"[2001:db8::1]:0"}}]
  }
}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.Client())
	client.BaseURL = server.URL
	client.APIVersion = "test"
	device, err := client.EnrollDevice(context.Background(), "device-id", "access-token", "public-key", KeyTypeMASQUE, TunnelMASQUE, "laptop")
	require.NoError(t, err)
	require.Equal(t, "device-id", device.ID)
	require.Equal(t, "172.16.0.2", device.Config.Interface.Addresses.V4)
	require.Len(t, device.Config.Peers, 1)
}

func TestAPIClientEscapesDeviceID(t *testing.T) {
	client := NewAPIClient(nil)
	client.BaseURL = "https://api.example"
	client.APIVersion = "version"
	require.Equal(t, "https://api.example/version/reg/device%2F..%2Faccount", client.endpoint("reg", "device/../account"))
}

func TestAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":1001,"message":"invalid public key"}]}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.Client())
	client.BaseURL = server.URL
	client.APIVersion = "test"
	_, err := client.GetDevice(context.Background(), "device", "token")
	require.Error(t, err)
	var apiError *APIError
	require.True(t, errors.As(err, &apiError))
	require.Equal(t, http.StatusUnauthorized, apiError.StatusCode)
	require.ErrorContains(t, err, "1001: invalid public key")
}

func TestAPIClientValidatesRegistrationInputs(t *testing.T) {
	client := NewAPIClient(nil)
	_, err := client.RegisterDevice(context.Background(), "")
	require.ErrorContains(t, err, "registration public key")

	_, err = client.EnrollDevice(context.Background(), "", "", "key", KeyTypeWireGuard, TunnelWireGuard, "")
	require.ErrorContains(t, err, "device ID and access token")

	_, err = client.EnrollDevice(context.Background(), "device", "token", "", KeyTypeWireGuard, TunnelWireGuard, "")
	require.ErrorContains(t, err, "enrollment public key")

	_, err = client.EnrollDevice(context.Background(), "device", "token", "key", KeyTypeWireGuard, TunnelMASQUE, "")
	require.ErrorContains(t, err, "unsupported enrollment")
}
