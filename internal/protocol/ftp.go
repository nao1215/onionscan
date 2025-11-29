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

// FTPScanner performs FTP scanning on onion services.
// It connects to port 21 to detect FTP servers and extract banner information.
//
// Design decision: FTP is included despite being an older protocol because:
//  1. Some onion services still use FTP for file sharing
//  2. Anonymous FTP may leak information
//  3. FTP servers often have verbose banners
type FTPScanner struct {
	// dialer is used to establish connections through Tor.
	dialer proxy.Dialer

	// timeout is the connection timeout.
	timeout time.Duration
}

// FTPScannerOption configures an FTPScanner.
type FTPScannerOption func(*FTPScanner)

// WithFTPTimeout sets the connection timeout for FTP scanning.
func WithFTPTimeout(timeout time.Duration) FTPScannerOption {
	return func(s *FTPScanner) {
		s.timeout = timeout
	}
}

// NewFTPScanner creates a new FTP scanner.
// The dialer should be configured to use the Tor SOCKS5 proxy.
func NewFTPScanner(dialer proxy.Dialer, opts ...FTPScannerOption) *FTPScanner {
	s := &FTPScanner{
		dialer:  dialer,
		timeout: 30 * time.Second,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Protocol returns the protocol name.
func (s *FTPScanner) Protocol() string {
	return "ftp"
}

// DefaultPort returns the default FTP port.
func (s *FTPScanner) DefaultPort() int {
	return 21
}

// Scan performs an FTP scan on the target.
// It connects to port 21 and reads the FTP welcome banner.
func (s *FTPScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	result := NewScanResult("ftp", 21)

	// Build target address
	host := strings.TrimPrefix(target, "ftp://")
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	if !strings.Contains(host, ":") {
		host = host + ":21"
	}

	// Create connection with timeout
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Connect to FTP port
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

	// Read the welcome banner (FTP sends 220 response immediately)
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		result.SetMetadata("banner_error", err.Error())
		return result, nil
	}

	// FTP may send multi-line banners (220- for continuation)
	var fullBanner strings.Builder
	fullBanner.WriteString(strings.TrimSpace(banner))

	// Check for multi-line response (220-)
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
func (s *FTPScanner) dialWithContext(ctx context.Context, network, address string) (net.Conn, error) {
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

// analyzeBanner analyzes the FTP banner for security information.
//
// FTP banners often contain:
//  1. Server software (vsFTPd, ProFTPD, Pure-FTPd, etc.)
//  2. Custom welcome messages (potentially identifying)
//  3. Organization or hostname information
func (s *FTPScanner) analyzeBanner(result *ScanResult) {
	banner := result.Banner
	lower := strings.ToLower(banner)

	// Detect FTP server software
	var serverType string
	switch {
	case strings.Contains(lower, "vsftpd"):
		serverType = "vsFTPd"
	case strings.Contains(lower, "proftpd"):
		serverType = "ProFTPD"
	case strings.Contains(lower, "pure-ftpd"):
		serverType = "Pure-FTPd"
	case strings.Contains(lower, "filezilla"):
		serverType = "FileZilla Server"
	case strings.Contains(lower, "microsoft ftp"):
		serverType = "Microsoft IIS FTP"
	}

	if serverType != "" {
		result.SetMetadata("ftp_server", serverType)
	}

	// Check for identifying information in banner
	s.checkBannerLeaks(result)

	// Version disclosure
	result.AddFinding(Finding{
		Title:       "FTP Banner Disclosed",
		Description: "The FTP server discloses information in its welcome banner.",
		Severity:    model.SeverityInfo,
		Value:       banner,
		Location:    "FTP Banner (Port 21)",
		Category:    "information-disclosure",
	})
}

// checkBannerLeaks checks for potentially identifying information in the FTP banner.
//
// Design decision: We check for common identifying patterns because:
//  1. Operators sometimes include identifying info in banners
//  2. Default banners may reveal server configuration
//  3. Custom messages may contain organization names
func (s *FTPScanner) checkBannerLeaks(result *ScanResult) {
	banner := result.Banner

	// Check for hostnames that might reveal identity
	// Look for patterns like "Welcome to server.example.com"
	if strings.Contains(strings.ToLower(banner), "welcome to") {
		// Check if it contains a domain name
		if strings.Contains(banner, ".") {
			// Could be a domain name
			result.AddFinding(Finding{
				Title:       "FTP Banner May Contain Hostname",
				Description: "The FTP welcome banner appears to contain a hostname or domain name which could identify the operator.",
				Severity:    model.SeverityMedium,
				Value:       banner,
				Location:    "FTP Banner",
				Category:    "information-disclosure",
			})
		}
	}

	// Check for server paths that might be revealing
	if strings.Contains(banner, "/") || strings.Contains(banner, "\\") {
		result.AddFinding(Finding{
			Title:       "FTP Banner Contains File Path",
			Description: "The FTP banner contains what appears to be a file system path, which may reveal server configuration.",
			Severity:    model.SeverityLow,
			Value:       banner,
			Location:    "FTP Banner",
			Category:    "information-disclosure",
		})
	}
}
