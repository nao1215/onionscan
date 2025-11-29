package protocol

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nao1215/onionscan/internal/model"
)

// HTTPScanner performs HTTP/HTTPS scanning on onion services.
// It detects web servers, collects headers, and identifies common
// misconfigurations that could leak identity.
//
// Design decision: We use a struct with the http.Client rather than
// passing the client on each call because:
//  1. Client configuration (proxy, timeouts) should be consistent
//  2. Connection pooling works better with a shared client
//  3. Easier to test with mock transport
type HTTPScanner struct {
	// client is the HTTP client configured for Tor proxy.
	client *http.Client

	// userAgent is the User-Agent header to use for requests.
	// Default simulates a standard browser to avoid fingerprinting.
	userAgent string

	// maxBodySize limits the response body size to prevent memory exhaustion.
	// Default is 10MB.
	maxBodySize int64

	// followRedirects controls whether to follow HTTP redirects.
	// Default is true, but limited to 10 redirects.
	followRedirects bool

	// timeout is the per-request timeout.
	timeout time.Duration
}

// HTTPScannerOption configures an HTTPScanner.
type HTTPScannerOption func(*HTTPScanner)

// WithUserAgent sets a custom User-Agent header.
// By default, we use a common browser User-Agent to blend in.
//
// Design decision: We allow customizing the User-Agent because:
//  1. Some sites behave differently based on User-Agent
//  2. Testing may require specific User-Agents
//  3. Default should be something common, not "OnionScan"
func WithUserAgent(ua string) HTTPScannerOption {
	return func(s *HTTPScanner) {
		s.userAgent = ua
	}
}

// WithMaxBodySize sets the maximum response body size.
// Default is 10MB to prevent memory exhaustion from large responses.
func WithMaxBodySize(size int64) HTTPScannerOption {
	return func(s *HTTPScanner) {
		s.maxBodySize = size
	}
}

// WithHTTPTimeout sets the per-request timeout.
func WithHTTPTimeout(timeout time.Duration) HTTPScannerOption {
	return func(s *HTTPScanner) {
		s.timeout = timeout
	}
}

// WithFollowRedirects controls redirect following behavior.
func WithFollowRedirects(follow bool) HTTPScannerOption {
	return func(s *HTTPScanner) {
		s.followRedirects = follow
	}
}

// NewHTTPScanner creates a new HTTP scanner with the given HTTP client.
// The client should be pre-configured with the Tor SOCKS5 proxy.
//
// Design decision: We require an external http.Client rather than
// creating one internally because:
//  1. Tor proxy configuration is handled by the tor package
//  2. Allows for different proxy configurations in tests
//  3. Connection pooling can be shared across scanners
func NewHTTPScanner(client *http.Client, opts ...HTTPScannerOption) *HTTPScanner {
	s := &HTTPScanner{
		client: client,
		// Default User-Agent mimics Firefox on Linux to blend in.
		// We avoid using "OnionScan" or similar identifying strings.
		userAgent:       "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
		maxBodySize:     10 * 1024 * 1024, // 10MB
		followRedirects: true,
		timeout:         30 * time.Second,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Protocol returns the protocol name.
func (s *HTTPScanner) Protocol() string {
	return "http"
}

// DefaultPort returns the default HTTP port.
func (s *HTTPScanner) DefaultPort() int {
	return 80
}

// Scan performs an HTTP scan on the target URL.
// It detects the web server, collects headers, and identifies issues.
func (s *HTTPScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	result := NewScanResult("http", 80)

	// Ensure target has a scheme
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	// Detect HTTPS
	if strings.HasPrefix(target, "https://") {
		result.Protocol = "https"
		result.Port = 443
		result.TLS = true
	}

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "close")

	// Perform request
	resp, err := s.client.Do(req)
	if err != nil {
		// Check if this is a timeout or connection refused
		// These are expected for non-existent services
		return result, nil
	}
	defer resp.Body.Close()

	// Service detected
	result.Detected = true

	// Copy headers
	result.Headers = resp.Header.Clone()

	// Extract server banner
	if server := resp.Header.Get("Server"); server != "" {
		result.Banner = server
	}

	// Extract TLS information if available
	if resp.TLS != nil {
		s.extractTLSInfo(result, resp.TLS)
	}

	// Read body with size limit
	bodyReader := io.LimitReader(resp.Body, s.maxBodySize)
	body, err := io.ReadAll(bodyReader)
	if err != nil {
		// Log but don't fail - we still have header information
		result.SetMetadata("body_read_error", err.Error())
	} else {
		result.SetMetadata("body", string(body))
		result.SetMetadata("body_size", len(body))
	}

	// Store target URL for additional checks (e.g., mod_status)
	result.SetMetadata("target_url", target)

	// Analyze headers for findings
	s.analyzeHeaders(result)

	return result, nil
}

// extractTLSInfo extracts certificate information from the TLS connection.
// This is important for identifying potential deanonymization vectors.
//
// Design decision: We only extract specific fields rather than the full
// certificate because:
//  1. Full cert is large and contains unnecessary data
//  2. Only certain fields are relevant for anonymity analysis
//  3. Simplifies JSON serialization
func (s *HTTPScanner) extractTLSInfo(result *ScanResult, state *tls.ConnectionState) {
	result.TLS = true

	// Record TLS version
	switch state.Version {
	case tls.VersionTLS10:
		result.TLSVersion = "TLS 1.0"
	case tls.VersionTLS11:
		result.TLSVersion = "TLS 1.1"
	case tls.VersionTLS12:
		result.TLSVersion = "TLS 1.2"
	case tls.VersionTLS13:
		result.TLSVersion = "TLS 1.3"
	default:
		result.TLSVersion = "Unknown"
	}

	// Extract certificate info if available
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Certificate = &CertificateInfo{
			Subject:             cert.Subject.String(),
			Issuer:              cert.Issuer.String(),
			NotBefore:           cert.NotBefore.Format(time.RFC3339),
			NotAfter:            cert.NotAfter.Format(time.RFC3339),
			SerialNumber:        cert.SerialNumber.String(),
			DNSNames:            cert.DNSNames,
			EmailAddresses:      cert.EmailAddresses,
			IssuingOrganization: strings.Join(cert.Issuer.Organization, ", "),
		}

		// Check for identity leaks in certificate
		s.analyzeCertificate(result)
	}
}

// analyzeCertificate checks for potential identity leaks in the TLS certificate.
func (s *HTTPScanner) analyzeCertificate(result *ScanResult) {
	if result.Certificate == nil {
		return
	}

	// DNS names may reveal clearnet domains
	for _, dns := range result.Certificate.DNSNames {
		// Skip .onion domains - those are expected
		if !strings.HasSuffix(dns, ".onion") {
			result.AddFinding(Finding{
				Title:       "TLS Certificate Contains Clearnet Domain",
				Description: "The TLS certificate contains a DNS name that is not an onion address. This could link this hidden service to a clearnet domain.",
				Severity:    model.SeverityHigh,
				Value:       dns,
				Location:    "TLS Certificate SAN",
				Category:    "certificate",
			})
		}
	}

	// Email addresses in certificates are major leaks
	for _, email := range result.Certificate.EmailAddresses {
		result.AddFinding(Finding{
			Title:       "TLS Certificate Contains Email Address",
			Description: "The TLS certificate contains an email address. This is a significant deanonymization vector.",
			Severity:    model.SeverityCritical,
			Value:       email,
			Location:    "TLS Certificate Email",
			Category:    "certificate",
		})
	}
}

// analyzeHeaders analyzes HTTP headers for security issues and information leaks.
//
// Design decision: We analyze headers in a dedicated method rather than inline
// because:
//  1. Header analysis is complex and protocol-specific
//  2. Easier to test individual header checks
//  3. Can be extended without modifying the main Scan method
func (s *HTTPScanner) analyzeHeaders(result *ScanResult) {
	// Check for Apache mod_status
	if s.checkModStatus(result) {
		result.AddFinding(Finding{
			Title:       "Apache mod_status Exposed",
			Description: "Apache mod_status is accessible. This exposes server information including IP addresses, uptime, and current connections.",
			Severity:    model.SeverityHigh,
			Location:    "/server-status",
			Category:    "misconfiguration",
		})
	}

	// Check server banner for version disclosure
	if server := result.Headers.Get("Server"); server != "" {
		// Verbose server headers reveal software and version
		if strings.Contains(server, "/") {
			result.AddFinding(Finding{
				Title:       "Server Version Disclosed",
				Description: "The server header reveals software version information. This helps attackers identify vulnerabilities.",
				Severity:    model.SeverityLow,
				Value:       server,
				Location:    "Server Header",
				Category:    "information-disclosure",
			})
		}
	}

	// Check X-Powered-By header
	if poweredBy := result.Headers.Get("X-Powered-By"); poweredBy != "" {
		result.AddFinding(Finding{
			Title:       "X-Powered-By Header Present",
			Description: "The X-Powered-By header reveals backend technology. This helps attackers fingerprint the application.",
			Severity:    model.SeverityLow,
			Value:       poweredBy,
			Location:    "X-Powered-By Header",
			Category:    "information-disclosure",
		})
	}

	// Check for missing security headers
	s.checkSecurityHeaders(result)

	// Check for ETag leaks (inode numbers)
	if etag := result.Headers.Get("ETag"); etag != "" {
		// Apache can leak inode numbers in weak ETags
		if strings.Contains(etag, "-") && !strings.HasPrefix(etag, "W/") {
			result.AddFinding(Finding{
				Title:       "ETag May Leak Inode Number",
				Description: "The ETag header appears to contain Apache-style weak tags that may include inode numbers.",
				Severity:    model.SeverityMedium,
				Value:       etag,
				Location:    "ETag Header",
				Category:    "information-disclosure",
			})
		}
	}
}

// checkModStatus attempts to detect Apache mod_status.
// It checks if /server-status is accessible, which can leak server information
// including client IP addresses and internal server details.
//
// Design decision: We only check if the server header indicates Apache,
// then make an additional request to /server-status. This avoids unnecessary
// requests to non-Apache servers.
func (s *HTTPScanner) checkModStatus(result *ScanResult) bool {
	// Only check Apache servers
	server := result.Headers.Get("Server")
	if !strings.Contains(strings.ToLower(server), "apache") {
		return false
	}

	// Skip if no client available
	if s.client == nil {
		return false
	}

	// Get the original target from metadata or reconstruct from result
	baseURL := result.GetMetadata("target_url")
	if baseURL == nil {
		return false
	}

	targetURL, ok := baseURL.(string)
	if !ok {
		return false
	}

	// Construct /server-status URL
	statusURL := strings.TrimSuffix(targetURL, "/") + "/server-status"

	// Create request with a fresh context and short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
	if err != nil {
		return false
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,*/*")

	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Check if we got a successful response
	if resp.StatusCode != http.StatusOK {
		return false
	}

	// Read limited body to check for mod_status indicators
	bodyReader := io.LimitReader(resp.Body, 64*1024) // 64KB limit for status page
	body, err := io.ReadAll(bodyReader)
	if err != nil {
		return false
	}

	bodyStr := string(body)

	// Check for typical mod_status content
	modStatusIndicators := []string{
		"Apache Server Status",
		"Server Version:",
		"Current Time:",
		"Restart Time:",
		"Total accesses:",
		"CPU Usage:",
		"requests currently being processed",
		"<title>Apache Status</title>",
	}

	for _, indicator := range modStatusIndicators {
		if strings.Contains(bodyStr, indicator) {
			// Store the status page content for analysis
			result.SetMetadata("mod_status_content", bodyStr)
			result.SetMetadata("mod_status_url", statusURL)
			return true
		}
	}

	return false
}

// checkSecurityHeaders checks for missing recommended security headers.
func (s *HTTPScanner) checkSecurityHeaders(result *ScanResult) {
	// Check Content-Security-Policy
	if csp := result.Headers.Get("Content-Security-Policy"); csp == "" {
		result.AddFinding(Finding{
			Title:       "Missing Content-Security-Policy Header",
			Description: "No Content-Security-Policy header is set. CSP helps prevent XSS and data injection attacks.",
			Severity:    model.SeverityInfo,
			Location:    "HTTP Headers",
			Category:    "security-headers",
		})
	}

	// Check X-Frame-Options
	if xfo := result.Headers.Get("X-Frame-Options"); xfo == "" {
		result.AddFinding(Finding{
			Title:       "Missing X-Frame-Options Header",
			Description: "No X-Frame-Options header is set. This may allow clickjacking attacks.",
			Severity:    model.SeverityInfo,
			Location:    "HTTP Headers",
			Category:    "security-headers",
		})
	}

	// Check X-Content-Type-Options
	if xcto := result.Headers.Get("X-Content-Type-Options"); xcto == "" {
		result.AddFinding(Finding{
			Title:       "Missing X-Content-Type-Options Header",
			Description: "No X-Content-Type-Options header is set. This may allow MIME type sniffing.",
			Severity:    model.SeverityInfo,
			Location:    "HTTP Headers",
			Category:    "security-headers",
		})
	}
}
