package protocol

import (
	"bufio"
	"context"
	"net"
	"strings"
	"time"

	"github.com/nao1215/onionscan/internal/model"
	"golang.org/x/net/proxy"
)

// SMTPScanner performs SMTP scanning on onion services.
// It connects to port 25 to detect mail servers and extract banner information.
//
// Design decision: SMTP scanning is important because:
//  1. Mail servers are common on onion services
//  2. SMTP banners often reveal hostnames and software
//  3. Mail server misconfiguration can leak identity
type SMTPScanner struct {
	// dialer is used to establish connections through Tor.
	dialer proxy.Dialer

	// timeout is the connection timeout.
	timeout time.Duration
}

// SMTPScannerOption configures an SMTPScanner.
type SMTPScannerOption func(*SMTPScanner)

// WithSMTPTimeout sets the connection timeout for SMTP scanning.
func WithSMTPTimeout(timeout time.Duration) SMTPScannerOption {
	return func(s *SMTPScanner) {
		s.timeout = timeout
	}
}

// NewSMTPScanner creates a new SMTP scanner.
// The dialer should be configured to use the Tor SOCKS5 proxy.
func NewSMTPScanner(dialer proxy.Dialer, opts ...SMTPScannerOption) *SMTPScanner {
	s := &SMTPScanner{
		dialer:  dialer,
		timeout: 30 * time.Second,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Protocol returns the protocol name.
func (s *SMTPScanner) Protocol() string {
	return "smtp"
}

// DefaultPort returns the default SMTP port.
func (s *SMTPScanner) DefaultPort() int {
	return 25
}

// Scan performs an SMTP scan on the target.
// It connects to port 25 and reads the SMTP greeting.
func (s *SMTPScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	result := NewScanResult("smtp", 25)

	// Build target address
	host := strings.TrimPrefix(target, "smtp://")
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	if !strings.Contains(host, ":") {
		host = host + ":25"
	}

	// Create connection with timeout
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Connect to SMTP port
	conn, err := s.dialWithContext(ctx, "tcp", host)
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	// Set read deadline
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return result, nil
	}

	// Service detected
	result.Detected = true

	// Read the greeting (SMTP sends 220 response immediately)
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		result.SetMetadata("banner_error", err.Error())
		return result, nil
	}

	// Handle multi-line greetings (220-hostname for continuation)
	var fullBanner strings.Builder
	fullBanner.WriteString(strings.TrimSpace(banner))

	for strings.HasPrefix(banner, "220-") {
		banner, err = reader.ReadString('\n')
		if err != nil {
			break
		}
		fullBanner.WriteString("\n")
		fullBanner.WriteString(strings.TrimSpace(banner))
		if strings.HasPrefix(banner, "220 ") {
			break
		}
	}

	result.Banner = fullBanner.String()

	// Analyze the banner
	s.analyzeBanner(result)

	return result, nil
}

// dialWithContext dials a connection respecting context cancellation.
func (s *SMTPScanner) dialWithContext(ctx context.Context, network, address string) (net.Conn, error) {
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

// analyzeBanner analyzes the SMTP banner for security information.
//
// SMTP banners typically reveal:
//  1. Hostname (often the actual clearnet hostname!)
//  2. Mail server software (Postfix, Exim, Sendmail, etc.)
//  3. Operating system information
func (s *SMTPScanner) analyzeBanner(result *ScanResult) {
	banner := result.Banner
	lower := strings.ToLower(banner)

	// Detect mail server software
	var serverType string
	switch {
	case strings.Contains(lower, "postfix"):
		serverType = "Postfix"
	case strings.Contains(lower, "exim"):
		serverType = "Exim"
	case strings.Contains(lower, "sendmail"):
		serverType = "Sendmail"
	case strings.Contains(lower, "microsoft"):
		serverType = "Microsoft Exchange"
	case strings.Contains(lower, "dovecot"):
		serverType = "Dovecot"
	case strings.Contains(lower, "zimbra"):
		serverType = "Zimbra"
	}

	if serverType != "" {
		result.SetMetadata("smtp_server", serverType)
	}

	// Extract hostname from banner
	// SMTP banners typically start with "220 hostname"
	s.extractHostname(result)

	// Check for common leaks
	s.checkBannerLeaks(result)

	// Banner disclosure
	result.AddFinding(Finding{
		Title:       "SMTP Banner Disclosed",
		Description: "The SMTP server discloses information in its greeting.",
		Severity:    model.SeverityInfo,
		Value:       banner,
		Location:    "SMTP Banner (Port 25)",
		Category:    "information-disclosure",
	})
}

// extractHostname attempts to extract a hostname from the SMTP banner.
//
// This is critical for deanonymization because SMTP servers often reveal
// their actual hostname, which may be a clearnet domain.
func (s *SMTPScanner) extractHostname(result *ScanResult) {
	banner := result.Banner

	// Remove the 220 prefix
	hostname := strings.TrimPrefix(banner, "220 ")
	hostname = strings.TrimPrefix(hostname, "220-")

	// Split by space - hostname is usually first word
	parts := strings.Fields(hostname)
	if len(parts) > 0 {
		hostname = parts[0]

		// Skip if it's an onion address
		if strings.HasSuffix(hostname, ".onion") {
			result.SetMetadata("smtp_hostname", hostname)
			return
		}

		// Check if it looks like a domain name
		if strings.Contains(hostname, ".") && !strings.Contains(hostname, "@") {
			result.SetMetadata("smtp_hostname", hostname)

			result.AddFinding(Finding{
				Title:       "SMTP Banner Reveals Hostname",
				Description: "The SMTP banner reveals a hostname that is not an onion address. This is a significant deanonymization vector as it likely reveals the clearnet identity of the server.",
				Severity:    model.SeverityCritical,
				Value:       hostname,
				Location:    "SMTP Banner",
				Category:    "hostname-leak",
			})
		}
	}
}

// checkBannerLeaks checks for additional identifying information in the banner.
func (s *SMTPScanner) checkBannerLeaks(result *ScanResult) {
	banner := result.Banner
	lower := strings.ToLower(banner)

	// Check for ESMTP (reveals Extended SMTP support)
	if strings.Contains(lower, "esmtp") {
		result.SetMetadata("esmtp", true)
	}

	// Check for explicit software version disclosure
	// e.g., "Postfix 3.4.14" or "Exim 4.94"
	if strings.Contains(banner, ".") {
		// Version numbers typically have digits and dots
		// This is a heuristic - version numbers like "3.4.14" indicate disclosure
		result.AddFinding(Finding{
			Title:       "SMTP Software Version Disclosed",
			Description: "The SMTP banner appears to contain software version information.",
			Severity:    model.SeverityLow,
			Value:       banner,
			Location:    "SMTP Banner",
			Category:    "information-disclosure",
		})
	}
}
