package protocol

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/nao1215/onionscan/internal/model"
	"golang.org/x/net/proxy"
)

// SSHScanner performs SSH scanning on onion services.
// It connects to port 22 to detect SSH servers and extract version information.
//
// Design decision: We use raw TCP connections rather than an SSH library because:
//  1. We only need to read the banner, not authenticate
//  2. Avoids dependency on complex SSH libraries
//  3. Banner is sent immediately upon connection
//  4. Minimizes attack surface by not implementing full SSH
type SSHScanner struct {
	// dialer is used to establish connections through Tor.
	dialer proxy.Dialer

	// timeout is the connection timeout.
	timeout time.Duration
}

// SSHScannerOption configures an SSHScanner.
type SSHScannerOption func(*SSHScanner)

// WithSSHTimeout sets the connection timeout for SSH scanning.
func WithSSHTimeout(timeout time.Duration) SSHScannerOption {
	return func(s *SSHScanner) {
		s.timeout = timeout
	}
}

// NewSSHScanner creates a new SSH scanner.
// The dialer should be configured to use the Tor SOCKS5 proxy.
//
// Design decision: We take a proxy.Dialer rather than creating one because:
//  1. Tor proxy configuration is handled by the tor package
//  2. Consistent with other scanners that take configured clients
//  3. Allows for testing with mock dialers
func NewSSHScanner(dialer proxy.Dialer, opts ...SSHScannerOption) *SSHScanner {
	s := &SSHScanner{
		dialer:  dialer,
		timeout: 30 * time.Second,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Protocol returns the protocol name.
func (s *SSHScanner) Protocol() string {
	return "ssh"
}

// DefaultPort returns the default SSH port.
func (s *SSHScanner) DefaultPort() int {
	return 22
}

// Scan performs an SSH scan on the target.
// It connects to port 22 and reads the SSH version banner.
func (s *SSHScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	result := NewScanResult("ssh", 22)

	// Build target address (strip protocol prefix if present)
	host := strings.TrimPrefix(target, "ssh://")
	// Remove any path
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	// Add port if not present
	if !strings.Contains(host, ":") {
		host = host + ":22"
	}

	// Create connection with timeout
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Connect to SSH port
	conn, err := s.dialWithContext(ctx, "tcp", host)
	if err != nil {
		// Connection refused or timeout - service not running
		return result, nil
	}
	defer conn.Close()

	// Set read deadline
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return result, nil
	}

	// Service detected
	result.Detected = true

	// Read the banner (SSH servers send version string immediately)
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		// Got connection but no banner - unusual
		result.SetMetadata("banner_error", err.Error())
		return result, nil
	}

	// Clean and store banner
	result.Banner = strings.TrimSpace(banner)

	// Analyze the banner for information
	s.analyzeBanner(result)

	return result, nil
}

// dialWithContext dials a connection respecting context cancellation.
//
// Design decision: We implement our own context-aware dial because
// net.Dialer.DialContext requires a network and address, but we need
// to support custom dialers (like SOCKS5 proxies).
func (s *SSHScanner) dialWithContext(ctx context.Context, network, address string) (net.Conn, error) {
	// Use a channel to receive the connection result
	type dialResult struct {
		conn net.Conn
		err  error
	}

	resultCh := make(chan dialResult, 1)

	go func() {
		conn, err := s.dialer.Dial(network, address)
		resultCh <- dialResult{conn, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-resultCh:
		return result.conn, result.err
	}
}

// analyzeBanner analyzes the SSH banner for security information.
//
// SSH banners typically have the format: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
// This reveals:
//  1. SSH protocol version (should be 2.0)
//  2. Server software and version (OpenSSH, Dropbear, etc.)
//  3. Potentially the OS distribution
func (s *SSHScanner) analyzeBanner(result *ScanResult) {
	banner := result.Banner

	// Check SSH protocol version
	if strings.HasPrefix(banner, "SSH-1") {
		result.AddFinding(Finding{
			Title:       "SSH Protocol Version 1 Detected",
			Description: "SSH protocol version 1 is deprecated and has known vulnerabilities. Only SSH-2 should be used.",
			Severity:    model.SeverityHigh,
			Value:       banner,
			Location:    "SSH Banner",
			Category:    "protocol-version",
		})
	}

	// Parse version info
	parts := strings.SplitN(banner, "-", 3)
	if len(parts) >= 3 {
		versionInfo := parts[2]
		result.SetMetadata("ssh_version_info", versionInfo)

		// Detect OS from banner
		s.detectOSFromBanner(result, versionInfo)

		// Check for known vulnerable versions
		s.checkVulnerableVersions(result, versionInfo)
	}

	// Version disclosure is informational
	result.AddFinding(Finding{
		Title:       "SSH Version Banner Disclosed",
		Description: "The SSH server discloses its version information. This helps attackers identify potential vulnerabilities.",
		Severity:    model.SeverityInfo,
		Value:       banner,
		Location:    "SSH Banner",
		Category:    "information-disclosure",
	})
}

// detectOSFromBanner attempts to detect the operating system from the SSH banner.
//
// Design decision: OS detection is important because:
//  1. It narrows down potential attack vectors
//  2. May correlate with other services
//  3. Helps identify if the operator is using common vs obscure setups
func (s *SSHScanner) detectOSFromBanner(result *ScanResult, versionInfo string) {
	lower := strings.ToLower(versionInfo)

	var os string
	switch {
	case strings.Contains(lower, "ubuntu"):
		os = "Ubuntu Linux"
	case strings.Contains(lower, "debian"):
		os = "Debian Linux"
	case strings.Contains(lower, "freebsd"):
		os = "FreeBSD"
	case strings.Contains(lower, "openbsd"):
		os = "OpenBSD"
	case strings.Contains(lower, "centos"):
		os = "CentOS Linux"
	case strings.Contains(lower, "fedora"):
		os = "Fedora Linux"
	case strings.Contains(lower, "raspbian"):
		os = "Raspbian (Raspberry Pi)"
	}

	if os != "" {
		result.SetMetadata("detected_os", os)
		result.AddFinding(Finding{
			Title:       "Operating System Detected from SSH Banner",
			Description: fmt.Sprintf("The SSH banner reveals the operating system: %s. This helps narrow down attack vectors.", os),
			Severity:    model.SeverityLow,
			Value:       os,
			Location:    "SSH Banner",
			Category:    "information-disclosure",
		})
	}
}

// checkVulnerableVersions checks for known vulnerable SSH versions.
// This is a simplified check - a full implementation would have a database
// of CVEs mapped to version ranges.
//
// Design decision: We only check for major known vulnerabilities because:
//  1. Complete CVE database would be large and need regular updates
//  2. Minor vulnerabilities may not be relevant for anonymity
//  3. Focus is on deanonymization, not comprehensive vulnerability scanning
func (s *SSHScanner) checkVulnerableVersions(result *ScanResult, versionInfo string) {
	lower := strings.ToLower(versionInfo)

	// Check for very old OpenSSH versions (before 7.0)
	// These have various known vulnerabilities
	if strings.Contains(lower, "openssh") {
		// Extract version number
		// Example: OpenSSH_8.9p1
		if idx := strings.Index(lower, "openssh_"); idx != -1 {
			versionPart := lower[idx+8:]
			// Check if major version is less than 7
			if len(versionPart) > 0 && versionPart[0] >= '1' && versionPart[0] <= '6' {
				result.AddFinding(Finding{
					Title:       "Outdated OpenSSH Version",
					Description: "This OpenSSH version is quite old and may have known vulnerabilities. Consider updating.",
					Severity:    model.SeverityMedium,
					Value:       versionInfo,
					Location:    "SSH Banner",
					Category:    "outdated-software",
				})
			}
		}
	}

	// Check for Dropbear (often on embedded devices)
	if strings.Contains(lower, "dropbear") {
		result.SetMetadata("ssh_server", "Dropbear")
		result.AddFinding(Finding{
			Title:       "Dropbear SSH Server Detected",
			Description: "Dropbear is commonly used on embedded devices and routers. This may indicate a resource-constrained environment.",
			Severity:    model.SeverityInfo,
			Value:       versionInfo,
			Location:    "SSH Banner",
			Category:    "fingerprinting",
		})
	}
}
