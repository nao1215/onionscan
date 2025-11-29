package tor

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// checkProxyTimeout is the timeout for checking if the Tor proxy is available.
// We use a short timeout here because this is just a connectivity check,
// not an actual request through Tor.
const checkProxyTimeout = 2 * time.Second

// Client provides Tor network connectivity.
// It wraps a SOCKS5 dialer and provides methods for creating HTTP clients
// and raw TCP connections through Tor.
//
// Design decision: We don't use tornago's higher-level Tor daemon management
// because OnionScan expects users to have their own Tor daemon running.
// We only use the SOCKS5 connectivity, which is standard Go functionality.
// If tornago provides optimizations, we can integrate them later.
type Client struct {
	// proxyAddress is the Tor SOCKS5 proxy address in "host:port" format.
	proxyAddress string

	// dialer is the SOCKS5 dialer for Tor connections.
	// We cache this to avoid recreating it for each connection.
	dialer proxy.Dialer

	// timeout is the default timeout for connections.
	timeout time.Duration
}

// NewClient creates a new Tor client with the given proxy address and timeout.
//
// The proxyAddress must be in "host:port" format (e.g., "127.0.0.1:9050").
// The timeout is used as the default for HTTP clients created by this client.
//
// This function validates the proxy address format but does not verify
// that the proxy is actually running. Call CheckConnection() to verify.
//
// Design decision: We don't connect to the proxy in the constructor because:
// 1. It allows creating the client even when Tor isn't running yet
// 2. It separates object creation from network operations
// 3. It allows for better testing with mock proxies
func NewClient(proxyAddress string, timeout time.Duration) (*Client, error) {
	// Validate proxy address format
	if !isValidProxyAddress(proxyAddress) {
		return nil, ErrInvalidProxyAddress
	}

	// Create the SOCKS5 dialer
	// We use nil for auth because Tor's SOCKS port typically doesn't require auth
	dialer, err := proxy.SOCKS5("tcp", proxyAddress, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	return &Client{
		proxyAddress: proxyAddress,
		dialer:       dialer,
		timeout:      timeout,
	}, nil
}

// isValidProxyAddress checks if the address is in valid "host:port" format.
// We use a simple check rather than a full URL parser because the format
// is very specific (no scheme, no path, just host and port).
func isValidProxyAddress(address string) bool {
	// Must contain exactly one colon separating host and port
	parts := strings.Split(address, ":")
	if len(parts) != 2 {
		return false
	}

	host := parts[0]
	port := parts[1]

	// Host must not be empty
	if host == "" {
		return false
	}

	// Port must be a valid number between 1 and 65535
	if port == "" {
		return false
	}

	// Validate port is a number in valid range
	portNum := 0
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
		portNum = portNum*10 + int(c-'0')
		// Early exit if port is too large
		if portNum > 65535 {
			return false
		}
	}

	// Port must be at least 1
	if portNum < 1 {
		return false
	}

	return true
}

// SOCKS5 protocol constants
const (
	socks5Version       = 0x05
	socks5AuthNone      = 0x00
	socks5AuthNoAccept  = 0xFF
	socks5CmdConnect    = 0x01
	socks5AddrTypeDomID = 0x03

	// socks5TestOnion is a synthetic .onion address used for SOCKS5 verification.
	// This is intentionally a non-existent address - we only need to verify the proxy
	// responds to SOCKS5 CONNECT requests, not that the connection succeeds.
	// Using a fake address avoids any interaction with real services.
	socks5TestOnion = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
)

// CheckConnection verifies that the Tor proxy is running and accessible.
// It returns a ProxyStatus indicating the result of the check.
//
// The check works by performing a SOCKS5 protocol handshake to verify:
// 1. The proxy speaks SOCKS5 protocol
// 2. The proxy accepts connections without authentication
// 3. The proxy can handle .onion domain connections
//
// Security note: This is more robust than just checking HTTP response strings,
// as a fake proxy attack cannot easily mimic proper SOCKS5 protocol behavior.
func (c *Client) CheckConnection(ctx context.Context) ProxyStatus {
	// Create a context with timeout for the check
	ctx, cancel := context.WithTimeout(ctx, checkProxyTimeout)
	defer cancel()

	// Create a dialer with the context
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", c.proxyAddress)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return ProxyStatusTimeout
		}
		return ProxyStatusCannotConnect
	}
	defer conn.Close()

	// Set a deadline for the SOCKS5 handshake
	if err := conn.SetDeadline(time.Now().Add(checkProxyTimeout)); err != nil {
		return ProxyStatusCannotConnect
	}

	// Step 1: SOCKS5 version negotiation
	// Client sends: version (1 byte) + num auth methods (1 byte) + auth methods (N bytes)
	// We offer no authentication (0x00) only
	_, err = conn.Write([]byte{socks5Version, 0x01, socks5AuthNone})
	if err != nil {
		return ProxyStatusCannotConnect
	}

	// Server responds: version (1 byte) + selected auth method (1 byte)
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return ProxyStatusTimeout
		}
		// Anything else means it didn't speak SOCKS5 properly
		return ProxyStatusWrongType
	}

	// Extract version and auth method from response
	version := authResp[0]
	authMethod := authResp[1]

	// Verify SOCKS5 version
	if version != socks5Version {
		return ProxyStatusWrongType
	}

	// Verify server accepts no auth (Tor SOCKS port uses this by default)
	if authMethod == socks5AuthNoAccept {
		// Server requires authentication - not typical for Tor
		return ProxyStatusWrongType
	}
	if authMethod != socks5AuthNone {
		// Unknown auth method selected
		return ProxyStatusWrongType
	}

	// Step 2: Verify the proxy can handle connection requests
	// We send a connection request to a test .onion address
	// The proxy should respond (even with failure for non-existent address)
	// This verifies it's actually proxying, not just accepting SOCKS5 handshakes
	testOnion := socks5TestOnion
	testPort := uint16(80)

	// Build CONNECT request: version + cmd + reserved + addr type + addr + port
	connectReq := []byte{
		socks5Version,
		socks5CmdConnect,
		0x00, // reserved
		socks5AddrTypeDomID,
		byte(len(testOnion)),
	}
	connectReq = append(connectReq, []byte(testOnion)...)
	connectReq = append(connectReq, byte(testPort>>8), byte(testPort&0xFF))

	_, err = conn.Write(connectReq)
	if err != nil {
		return ProxyStatusCannotConnect
	}

	// Read response header: version + reply + reserved + addr type (at least 4 bytes)
	// We only need to verify the proxy responds to the connect request
	// The actual connection may fail (that's fine - we're just testing the proxy)
	connectResp := make([]byte, 4)
	if _, err := io.ReadFull(conn, connectResp); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return ProxyStatusTimeout
		}
		// If we got any bytes back but not enough, treat as wrong type
		return ProxyStatusWrongType
	}

	// Verify SOCKS5 version in response
	if connectResp[0] != socks5Version {
		return ProxyStatusWrongType
	}

	// Any response (success=0x00 or failure codes like 0x01-0x08) indicates
	// the proxy is working. Tor will return 0x04 (Host unreachable) or
	// 0x01 (General failure) for invalid/non-existent .onion addresses,
	// but the important thing is it processed the SOCKS5 request.
	return ProxyStatusOK
}

// NewHTTPClient creates an HTTP client configured to use the Tor proxy.
// The returned client routes all requests through Tor's SOCKS5 proxy.
//
// Design decisions:
// - TLS verification is disabled because hidden services use self-signed certs
// - We enable cookies via a cookie jar for session management during crawling
// - Redirect limit is 10 to prevent redirect loops while allowing normal redirects
// - Idle connection timeout is shorter than default to manage Tor circuit resources
func (c *Client) NewHTTPClient() *http.Client {
	// Create transport that routes through Tor
	transport := &http.Transport{
		// Use our SOCKS5 dialer for all connections
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			return c.dialer.Dial(network, addr)
		},
		// Disable TLS verification because hidden services typically use
		// self-signed certificates. The .onion address itself provides
		// authentication via the onion service protocol.
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // Required for .onion services
		},
		// Connection pool settings
		// We use smaller values than defaults because each connection goes
		// through a Tor circuit, which is a limited resource
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
		// Disable compression to mitigate CRIME/BREACH-style side-channel attacks.
		// While compression reduces data transferred, it can allow attackers to
		// infer content based on compressed response sizes, which is particularly
		// concerning for anonymity-focused Tor connections. The bandwidth savings
		// are not worth the potential privacy/anonymity risks.
		DisableCompression: true,
	}

	// Create cookie jar for session management
	// This allows crawling authenticated areas when a session cookie is provided
	jar, _ := cookiejar.New(nil) //nolint:errcheck // cookiejar.New only fails with invalid options

	return &http.Client{
		Transport: transport,
		Timeout:   c.timeout,
		Jar:       jar,
		// Limit redirects to prevent loops
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// Dial establishes a TCP connection through Tor to the given address.
// This is useful for non-HTTP protocols like SSH, FTP, etc.
//
// The address should be in "host:port" format. For hidden services,
// use the .onion address (e.g., "example.onion:22").
func (c *Client) Dial(network, address string) (net.Conn, error) {
	return c.dialer.Dial(network, address)
}

// DialContext establishes a TCP connection through Tor with context support.
// This allows for timeout and cancellation control.
//
// Design decision: We wrap the basic Dial with context support because
// the proxy.Dialer interface doesn't support context directly. If the context
// is cancelled, the goroutine returns the error but the underlying connection
// attempt may continue briefly. This is a known limitation of the approach.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// Create channels for result and error
	type dialResult struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan dialResult, 1)

	// Dial in a goroutine so we can respect context cancellation
	go func() {
		conn, err := c.dialer.Dial(network, address)
		resultCh <- dialResult{conn, err}
	}()

	// Wait for either the dial to complete or context cancellation
	select {
	case result := <-resultCh:
		return result.conn, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ProxyAddress returns the configured proxy address.
func (c *Client) ProxyAddress() string {
	return c.proxyAddress
}

// HTTPClient returns a new HTTP client configured for Tor.
// This is a convenience method that calls NewHTTPClient().
func (c *Client) HTTPClient() *http.Client {
	return c.NewHTTPClient()
}

// Dialer returns the underlying proxy dialer.
// This is useful for protocol scanners that need direct TCP connections.
//
// Design decision: We expose the dialer because:
// 1. Protocol scanners need it for non-HTTP connections
// 2. It allows for more flexible connection management
// 3. The caller can wrap it with additional functionality
func (c *Client) Dialer() proxy.Dialer {
	return c.dialer
}

// HTTPClientWithConfig creates an HTTP client with custom cookie and headers.
// This is useful for authenticated scanning where site-specific credentials
// are needed.
//
// The cookie parameter is a raw cookie string (e.g., "session_id=abc123").
// The headers parameter is a map of header names to values.
//
// Design decision: We use a custom RoundTripper to inject headers/cookies
// rather than modifying each request. This ensures all requests (including
// redirects and subrequests) include the configured values.
func (c *Client) HTTPClientWithConfig(cookie string, headers map[string]string) *http.Client {
	// Get base client
	client := c.NewHTTPClient()

	// Wrap transport with header/cookie injector
	client.Transport = &headerInjectingTransport{
		base:    client.Transport,
		cookie:  cookie,
		headers: headers,
	}

	return client
}

// headerInjectingTransport wraps an http.RoundTripper to inject
// custom headers and cookies into every request.
type headerInjectingTransport struct {
	base    http.RoundTripper
	cookie  string
	headers map[string]string
}

// RoundTrip implements http.RoundTripper.
func (t *headerInjectingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	clone := req.Clone(req.Context())

	// Inject cookie if configured
	if t.cookie != "" {
		// Append to existing Cookie header or set new one
		if existing := clone.Header.Get("Cookie"); existing != "" {
			clone.Header.Set("Cookie", existing+"; "+t.cookie)
		} else {
			clone.Header.Set("Cookie", t.cookie)
		}
	}

	// Inject custom headers
	for key, value := range t.headers {
		clone.Header.Set(key, value)
	}

	return t.base.RoundTrip(clone)
}
