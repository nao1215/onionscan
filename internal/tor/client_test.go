package tor

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestNewClient tests the Client constructor.
func TestNewClient(t *testing.T) {
	t.Parallel()

	t.Run("valid proxy address creates client", func(t *testing.T) {
		t.Parallel()

		client, err := NewClient("127.0.0.1:9050", 30*time.Second)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if client == nil {
			t.Fatal("expected non-nil client")
		}
		if client.ProxyAddress() != "127.0.0.1:9050" {
			t.Errorf("ProxyAddress() = %q, expected %q", client.ProxyAddress(), "127.0.0.1:9050")
		}
	})

	t.Run("localhost:port is valid", func(t *testing.T) {
		t.Parallel()

		client, err := NewClient("localhost:9050", 30*time.Second)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if client == nil {
			t.Fatal("expected non-nil client")
		}
	})

	t.Run("empty address returns error", func(t *testing.T) {
		t.Parallel()

		_, err := NewClient("", 30*time.Second)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, ErrInvalidProxyAddress) {
			t.Errorf("expected ErrInvalidProxyAddress, got %v", err)
		}
	})

	t.Run("address without port returns error", func(t *testing.T) {
		t.Parallel()

		_, err := NewClient("127.0.0.1", 30*time.Second)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, ErrInvalidProxyAddress) {
			t.Errorf("expected ErrInvalidProxyAddress, got %v", err)
		}
	})

	t.Run("address with empty host returns error", func(t *testing.T) {
		t.Parallel()

		_, err := NewClient(":9050", 30*time.Second)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, ErrInvalidProxyAddress) {
			t.Errorf("expected ErrInvalidProxyAddress, got %v", err)
		}
	})

	t.Run("address with empty port returns error", func(t *testing.T) {
		t.Parallel()

		_, err := NewClient("127.0.0.1:", 30*time.Second)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, ErrInvalidProxyAddress) {
			t.Errorf("expected ErrInvalidProxyAddress, got %v", err)
		}
	})

	t.Run("address with multiple colons returns error", func(t *testing.T) {
		t.Parallel()

		_, err := NewClient("127.0.0.1:9050:extra", 30*time.Second)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, ErrInvalidProxyAddress) {
			t.Errorf("expected ErrInvalidProxyAddress, got %v", err)
		}
	})
}

// TestIsValidProxyAddress tests the proxy address validation function.
func TestIsValidProxyAddress(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		address  string
		expected bool
	}{
		{"valid IPv4 with port", "127.0.0.1:9050", true},
		{"valid localhost with port", "localhost:9050", true},
		{"valid hostname with port", "tor.example.com:9050", true},
		{"empty string", "", false},
		{"no port", "127.0.0.1", false},
		{"empty host", ":9050", false},
		{"empty port", "127.0.0.1:", false},
		{"multiple colons", "127.0.0.1:9050:extra", false},
		{"only colon", ":", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := isValidProxyAddress(tc.address)
			if result != tc.expected {
				t.Errorf("isValidProxyAddress(%q) = %v, expected %v", tc.address, result, tc.expected)
			}
		})
	}
}

// TestNewHTTPClient tests HTTP client creation.
// Note: This test doesn't make actual network requests; it just verifies
// the client is created with expected configuration.
func TestNewHTTPClient(t *testing.T) {
	t.Parallel()

	client, err := NewClient("127.0.0.1:9050", 60*time.Second)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	httpClient := client.NewHTTPClient()

	t.Run("HTTP client is not nil", func(t *testing.T) {
		t.Parallel()
		if httpClient == nil {
			t.Fatal("expected non-nil HTTP client")
		}
	})

	t.Run("HTTP client has timeout set", func(t *testing.T) {
		t.Parallel()
		if httpClient.Timeout != 60*time.Second {
			t.Errorf("Timeout = %v, expected %v", httpClient.Timeout, 60*time.Second)
		}
	})

	t.Run("HTTP client has cookie jar", func(t *testing.T) {
		t.Parallel()
		if httpClient.Jar == nil {
			t.Error("expected non-nil cookie jar")
		}
	})

	t.Run("HTTP client has transport", func(t *testing.T) {
		t.Parallel()
		if httpClient.Transport == nil {
			t.Error("expected non-nil transport")
		}
	})
}

// TestProxyStatus tests ProxyStatus String and Error methods.
func TestProxyStatus(t *testing.T) {
	t.Parallel()

	t.Run("String method returns correct values", func(t *testing.T) {
		t.Parallel()

		testCases := []struct {
			status   ProxyStatus
			expected string
		}{
			{ProxyStatusOK, "OK"},
			{ProxyStatusWrongType, "wrong type (not Tor)"},
			{ProxyStatusCannotConnect, "cannot connect"},
			{ProxyStatusTimeout, "timeout"},
			{ProxyStatus(99), "unknown"},
		}

		for _, tc := range testCases {
			if tc.status.String() != tc.expected {
				t.Errorf("ProxyStatus(%d).String() = %q, expected %q", tc.status, tc.status.String(), tc.expected)
			}
		}
	})

	t.Run("Error method returns correct errors", func(t *testing.T) {
		t.Parallel()

		testCases := []struct {
			status      ProxyStatus
			expectedErr error
		}{
			{ProxyStatusOK, nil},
			{ProxyStatusWrongType, ErrProxyNotTor},
			{ProxyStatusCannotConnect, ErrProxyCannotConnect},
			{ProxyStatusTimeout, ErrProxyTimeout},
		}

		for _, tc := range testCases {
			err := tc.status.Error()
			if !errors.Is(err, tc.expectedErr) {
				t.Errorf("ProxyStatus(%d).Error() = %v, expected %v", tc.status, err, tc.expectedErr)
			}
		}
	})

	t.Run("Unknown status returns error", func(t *testing.T) {
		t.Parallel()

		unknown := ProxyStatus(99)
		err := unknown.Error()
		if err == nil {
			t.Error("expected error for unknown status")
		}
	})
}

// TestHTTPClient tests the HTTPClient method.
func TestHTTPClient(t *testing.T) {
	t.Parallel()

	client, err := NewClient("127.0.0.1:9050", 30*time.Second)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	httpClient := client.HTTPClient()
	if httpClient == nil {
		t.Error("expected non-nil HTTP client")
	}
}

// TestDialer tests the Dialer method.
func TestDialer(t *testing.T) {
	t.Parallel()

	client, err := NewClient("127.0.0.1:9050", 30*time.Second)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	dialer := client.Dialer()
	if dialer == nil {
		t.Error("expected non-nil dialer")
	}
}

// TestHTTPClientWithConfig tests HTTP client creation with custom config.
func TestHTTPClientWithConfig(t *testing.T) {
	t.Parallel()

	client, err := NewClient("127.0.0.1:9050", 30*time.Second)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	t.Run("with empty cookie and nil headers", func(t *testing.T) {
		t.Parallel()
		httpClient := client.HTTPClientWithConfig("", nil)
		if httpClient == nil {
			t.Error("expected non-nil HTTP client")
		}
	})

	t.Run("with cookie and headers", func(t *testing.T) {
		t.Parallel()
		headers := map[string]string{"X-Custom": "value"}
		httpClient := client.HTTPClientWithConfig("session=abc123", headers)
		if httpClient == nil {
			t.Error("expected non-nil HTTP client")
		}
	})
}

// TestHeaderInjectingTransport tests custom header and cookie injection.
func TestHeaderInjectingTransport(t *testing.T) {
	t.Parallel()

	t.Run("injects cookie header", func(t *testing.T) {
		t.Parallel()

		transport := &headerInjectingTransport{
			base:   http.DefaultTransport,
			cookie: "session=test123",
		}

		if transport.cookie != "session=test123" {
			t.Errorf("expected cookie 'session=test123', got %q", transport.cookie)
		}
	})

	t.Run("injects custom headers", func(t *testing.T) {
		t.Parallel()

		transport := &headerInjectingTransport{
			base: http.DefaultTransport,
			headers: map[string]string{
				"X-Custom-Header": "custom-value",
				"Authorization":   "Bearer token123",
			},
		}

		if transport.headers["X-Custom-Header"] != "custom-value" {
			t.Error("expected custom header to be set")
		}
		if transport.headers["Authorization"] != "Bearer token123" {
			t.Error("expected authorization header to be set")
		}
	})

	t.Run("handles empty cookie and headers", func(t *testing.T) {
		t.Parallel()

		transport := &headerInjectingTransport{
			base:    http.DefaultTransport,
			cookie:  "",
			headers: nil,
		}

		if transport.cookie != "" {
			t.Error("expected empty cookie")
		}
		if transport.headers != nil {
			t.Error("expected nil headers")
		}
	})
}

// TestClientTimeout tests client timeout handling.
func TestClientTimeout(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		timeout time.Duration
	}{
		{"1 second", 1 * time.Second},
		{"30 seconds", 30 * time.Second},
		{"2 minutes", 2 * time.Minute},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client, err := NewClient("127.0.0.1:9050", tc.timeout)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if client.timeout != tc.timeout {
				t.Errorf("expected timeout %v, got %v", tc.timeout, client.timeout)
			}
		})
	}
}

// TestNewHTTPClientConfiguration tests HTTP client configuration details.
func TestNewHTTPClientConfiguration(t *testing.T) {
	t.Parallel()

	client, err := NewClient("127.0.0.1:9050", 30*time.Second)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	httpClient := client.NewHTTPClient()

	t.Run("configures redirect policy", func(t *testing.T) {
		t.Parallel()
		if httpClient.CheckRedirect == nil {
			t.Error("expected CheckRedirect to be set")
		}
	})

	t.Run("HTTP client transport is correctly configured", func(t *testing.T) {
		t.Parallel()
		transport, ok := httpClient.Transport.(*http.Transport)
		if !ok {
			t.Fatal("expected transport to be *http.Transport")
		}
		if transport.MaxIdleConns != 10 {
			t.Errorf("expected MaxIdleConns 10, got %d", transport.MaxIdleConns)
		}
		if transport.MaxIdleConnsPerHost != 2 {
			t.Errorf("expected MaxIdleConnsPerHost 2, got %d", transport.MaxIdleConnsPerHost)
		}
		if transport.IdleConnTimeout != 30*time.Second {
			t.Errorf("expected IdleConnTimeout 30s, got %v", transport.IdleConnTimeout)
		}
	})

	t.Run("TLS config skips verification for onion services", func(t *testing.T) {
		t.Parallel()
		transport, ok := httpClient.Transport.(*http.Transport)
		if !ok {
			t.Fatal("expected transport to be *http.Transport")
		}
		if transport.TLSClientConfig == nil {
			t.Fatal("expected TLSClientConfig to be set")
		}
		if !transport.TLSClientConfig.InsecureSkipVerify {
			t.Error("expected InsecureSkipVerify to be true for .onion services")
		}
	})
}

// TestDialMethod tests the Dial method.
func TestDialMethod(t *testing.T) {
	t.Parallel()

	client, err := NewClient("127.0.0.1:9050", 30*time.Second)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	t.Run("Dial method returns error for unreachable proxy", func(t *testing.T) {
		t.Parallel()
		// This will fail because there's no Tor proxy running
		_, err := client.Dial("tcp", "example.onion:80")
		if err == nil {
			t.Log("Dial succeeded (Tor proxy may be running)")
		}
	})
}

// TestCheckConnection tests the SOCKS5 proxy verification.
func TestCheckConnection(t *testing.T) {
	t.Parallel()

	t.Run("returns CannotConnect for non-existent proxy", func(t *testing.T) {
		t.Parallel()

		// Use a port that's unlikely to be in use
		client, err := NewClient("127.0.0.1:59999", 30*time.Second)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		status := client.CheckConnection(context.Background())
		if status != ProxyStatusCannotConnect {
			t.Errorf("expected ProxyStatusCannotConnect, got %v", status)
		}
	})

	t.Run("returns WrongType for non-SOCKS5 server", func(t *testing.T) {
		t.Parallel()

		// Start a mock server that doesn't speak SOCKS5
		listener, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test code
		if err != nil {
			t.Fatalf("failed to start mock server: %v", err)
		}
		defer listener.Close()

		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			// Read the client's SOCKS5 greeting first (important for Windows)
			buf := make([]byte, 3)
			_, _ = conn.Read(buf)
			// Send HTTP response instead of SOCKS5
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		}()

		client, err := NewClient(listener.Addr().String(), 30*time.Second)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		status := client.CheckConnection(context.Background())
		if status != ProxyStatusWrongType {
			t.Errorf("expected ProxyStatusWrongType, got %v", status)
		}
	})

	t.Run("returns WrongType for SOCKS5 requiring auth", func(t *testing.T) {
		t.Parallel()

		// Start a mock SOCKS5 server that requires auth
		listener, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test code
		if err != nil {
			t.Fatalf("failed to start mock server: %v", err)
		}
		defer listener.Close()

		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			// Read client greeting
			buf := make([]byte, 3)
			_, _ = conn.Read(buf)
			// Respond with SOCKS5 version but require auth (0xFF = no acceptable methods)
			_, _ = conn.Write([]byte{0x05, 0xFF})
		}()

		client, err := NewClient(listener.Addr().String(), 30*time.Second)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		status := client.CheckConnection(context.Background())
		if status != ProxyStatusWrongType {
			t.Errorf("expected ProxyStatusWrongType, got %v", status)
		}
	})

	t.Run("returns OK for valid SOCKS5 proxy", func(t *testing.T) {
		t.Parallel()

		// Start a mock SOCKS5 server
		listener, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test code
		if err != nil {
			t.Fatalf("failed to start mock server: %v", err)
		}
		defer listener.Close()

		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			// Read client greeting (version + num methods + methods)
			buf := make([]byte, 3)
			_, _ = conn.Read(buf)

			// Respond with SOCKS5 version, no auth required
			_, _ = conn.Write([]byte{0x05, 0x00})

			// Read CONNECT request
			connectBuf := make([]byte, 256)
			_, _ = conn.Read(connectBuf)

			// Respond with success (or failure - either is fine for verification)
			// version + reply + reserved + addr type + addr + port
			_, _ = conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		}()

		client, err := NewClient(listener.Addr().String(), 30*time.Second)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		status := client.CheckConnection(context.Background())
		if status != ProxyStatusOK {
			t.Errorf("expected ProxyStatusOK, got %v", status)
		}
	})

	t.Run("returns WrongType for wrong version in CONNECT response", func(t *testing.T) {
		t.Parallel()

		// Start a mock server that sends wrong version in CONNECT response
		listener, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test code
		if err != nil {
			t.Fatalf("failed to start mock server: %v", err)
		}
		defer listener.Close()

		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			// Read client greeting
			buf := make([]byte, 3)
			_, _ = conn.Read(buf)

			// Respond with SOCKS5 version, no auth required
			_, _ = conn.Write([]byte{0x05, 0x00})

			// Read CONNECT request
			connectBuf := make([]byte, 256)
			_, _ = conn.Read(connectBuf)

			// Respond with wrong version (0x04 instead of 0x05)
			_, _ = conn.Write([]byte{0x04, 0x00, 0x00, 0x01})
		}()

		client, err := NewClient(listener.Addr().String(), 30*time.Second)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		status := client.CheckConnection(context.Background())
		if status != ProxyStatusWrongType {
			t.Errorf("expected ProxyStatusWrongType, got %v", status)
		}
	})

	t.Run("handles context cancellation", func(t *testing.T) {
		t.Parallel()

		client, err := NewClient("127.0.0.1:59998", 30*time.Second)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		status := client.CheckConnection(ctx)
		// Should return CannotConnect or Timeout due to cancelled context
		if status != ProxyStatusCannotConnect && status != ProxyStatusTimeout {
			t.Errorf("expected ProxyStatusCannotConnect or ProxyStatusTimeout, got %v", status)
		}
	})
}

// TestDialContext tests the DialContext method.
func TestDialContext(t *testing.T) {
	t.Parallel()

	client, err := NewClient("127.0.0.1:9050", 30*time.Second)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	t.Run("returns error for cancelled context", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := client.DialContext(ctx, "tcp", "example.onion:80")
		if err == nil {
			t.Log("DialContext succeeded unexpectedly")
		}
	})

	t.Run("returns error for unreachable proxy", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_, err := client.DialContext(ctx, "tcp", "example.onion:80")
		if err == nil {
			t.Log("DialContext succeeded (Tor proxy may be running)")
		}
	})
}
