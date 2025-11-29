package protocol

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nao1215/onionscan/internal/model"
)

// TestNewScanResult tests ScanResult creation and methods.
func TestNewScanResult(t *testing.T) {
	t.Parallel()

	t.Run("creates result with initialized maps", func(t *testing.T) {
		t.Parallel()

		result := NewScanResult("http", 80)

		if result.Protocol != "http" {
			t.Errorf("expected protocol 'http', got %q", result.Protocol)
		}
		if result.Port != 80 {
			t.Errorf("expected port 80, got %d", result.Port)
		}
		if result.Metadata == nil {
			t.Error("expected Metadata to be initialized")
		}
		if result.Headers == nil {
			t.Error("expected Headers to be initialized")
		}
		if result.Findings == nil {
			t.Error("expected Findings to be initialized")
		}
	})

	t.Run("AddFinding appends findings", func(t *testing.T) {
		t.Parallel()

		result := NewScanResult("http", 80)
		result.AddFinding(Finding{
			Title:    "Test Finding",
			Severity: model.SeverityHigh,
		})

		if len(result.Findings) != 1 {
			t.Errorf("expected 1 finding, got %d", len(result.Findings))
		}
		if result.Findings[0].Title != "Test Finding" {
			t.Errorf("expected title 'Test Finding', got %q", result.Findings[0].Title)
		}
	})

	t.Run("SetMetadata and GetMetadata work correctly", func(t *testing.T) {
		t.Parallel()

		result := NewScanResult("http", 80)
		result.SetMetadata("key", "value")

		got := result.GetMetadata("key")
		if got != "value" {
			t.Errorf("expected 'value', got %v", got)
		}

		// Non-existent key returns nil
		got = result.GetMetadata("nonexistent")
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
}

// TestHTTPScanner tests HTTP scanning functionality.
func TestHTTPScanner(t *testing.T) {
	t.Parallel()

	t.Run("detects web server and extracts headers", func(t *testing.T) {
		t.Parallel()

		// Create test server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Server", "nginx/1.18.0")
			w.Header().Set("X-Powered-By", "PHP/7.4")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>Test</body></html>")) //nolint:errcheck
		}))
		defer server.Close()

		scanner := NewHTTPScanner(server.Client())
		ctx := context.Background()

		result, err := scanner.Scan(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Detected {
			t.Error("expected service to be detected")
		}
		if result.Banner != "nginx/1.18.0" {
			t.Errorf("expected banner 'nginx/1.18.0', got %q", result.Banner)
		}
		if result.Headers.Get("X-Powered-By") != "PHP/7.4" {
			t.Error("expected X-Powered-By header")
		}
	})

	t.Run("identifies security header issues", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// No security headers
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		scanner := NewHTTPScanner(server.Client())
		ctx := context.Background()

		result, err := scanner.Scan(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should have findings about missing security headers
		hasCSPFinding := false
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "Content-Security-Policy") {
				hasCSPFinding = true
				break
			}
		}
		if !hasCSPFinding {
			t.Error("expected finding about missing CSP header")
		}
	})

	t.Run("handles version disclosure", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		scanner := NewHTTPScanner(server.Client())
		ctx := context.Background()

		result, err := scanner.Scan(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		hasVersionFinding := false
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "Version Disclosed") {
				hasVersionFinding = true
				break
			}
		}
		if !hasVersionFinding {
			t.Error("expected finding about server version disclosure")
		}
	})

	t.Run("respects max body size option", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// Send 1KB response
			_, _ = w.Write([]byte(strings.Repeat("x", 1024))) //nolint:errcheck
		}))
		defer server.Close()

		// Limit to 100 bytes
		scanner := NewHTTPScanner(server.Client(), WithMaxBodySize(100))
		ctx := context.Background()

		result, err := scanner.Scan(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		bodySize := result.GetMetadata("body_size")
		if bodySize == nil {
			t.Fatal("expected body_size metadata")
		}
		size, ok := bodySize.(int)
		if !ok {
			t.Fatal("body_size is not an int")
		}
		if size > 100 {
			t.Errorf("expected body size <= 100, got %d", size)
		}
	})
}

// TestHTTPScannerOptions tests HTTPScanner option functions.
func TestHTTPScannerOptions(t *testing.T) {
	t.Parallel()

	t.Run("WithUserAgent sets custom user agent", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient, WithUserAgent("CustomAgent/1.0"))
		if scanner.userAgent != "CustomAgent/1.0" {
			t.Errorf("expected 'CustomAgent/1.0', got %q", scanner.userAgent)
		}
	})

	t.Run("WithMaxBodySize sets size limit", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient, WithMaxBodySize(1024))
		if scanner.maxBodySize != 1024 {
			t.Errorf("expected 1024, got %d", scanner.maxBodySize)
		}
	})
}

// TestNormalizeHost tests the host normalization helper.
func TestNormalizeHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		target      string
		defaultPort string
		expected    string
	}{
		{
			name:        "adds default port",
			target:      "example.onion",
			defaultPort: "27017",
			expected:    "example.onion:27017",
		},
		{
			name:        "preserves existing port",
			target:      "example.onion:1234",
			defaultPort: "27017",
			expected:    "example.onion:1234",
		},
		{
			name:        "strips mongodb prefix",
			target:      "mongodb://example.onion",
			defaultPort: "27017",
			expected:    "example.onion:27017",
		},
		{
			name:        "strips redis prefix",
			target:      "redis://example.onion",
			defaultPort: "6379",
			expected:    "example.onion:6379",
		},
		{
			name:        "strips credentials",
			target:      "user:pass@example.onion",
			defaultPort: "5432",
			expected:    "example.onion:5432",
		},
		{
			name:        "strips path",
			target:      "postgresql://example.onion/database",
			defaultPort: "5432",
			expected:    "example.onion:5432",
		},
		{
			name:        "strips query parameters",
			target:      "mysql://example.onion?timeout=10s",
			defaultPort: "3306",
			expected:    "example.onion:3306",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := normalizeHost(tt.target, tt.defaultPort)
			if got != tt.expected {
				t.Errorf("normalizeHost(%q, %q) = %q, want %q",
					tt.target, tt.defaultPort, got, tt.expected)
			}
		})
	}
}

// TestSSHScanner tests SSH scanning functionality.
func TestSSHScanner(t *testing.T) {
	t.Parallel()

	t.Run("creates scanner with defaults", func(t *testing.T) {
		t.Parallel()

		scanner := NewSSHScanner(nil)

		if scanner.Protocol() != "ssh" {
			t.Errorf("expected protocol 'ssh', got %q", scanner.Protocol())
		}
		if scanner.DefaultPort() != 22 {
			t.Errorf("expected port 22, got %d", scanner.DefaultPort())
		}
	})

	t.Run("WithSSHTimeout sets timeout", func(t *testing.T) {
		t.Parallel()

		scanner := NewSSHScanner(nil, WithSSHTimeout(10))

		if scanner.timeout != 10 {
			t.Errorf("expected timeout 10, got %v", scanner.timeout)
		}
	})
}

// TestSSHBannerAnalysis tests SSH banner analysis.
func TestSSHBannerAnalysis(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		banner           string
		expectOS         bool
		expectOSValue    string
		expectVulnerable bool
		expectDropbear   bool
		expectSSHv1      bool
	}{
		{
			name:          "Ubuntu detection",
			banner:        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
			expectOS:      true,
			expectOSValue: "Ubuntu Linux",
		},
		{
			name:          "Debian detection",
			banner:        "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1",
			expectOS:      true,
			expectOSValue: "Debian Linux",
		},
		{
			name:          "FreeBSD detection",
			banner:        "SSH-2.0-OpenSSH_8.8 FreeBSD-20211221",
			expectOS:      true,
			expectOSValue: "FreeBSD",
		},
		{
			name:          "OpenBSD detection",
			banner:        "SSH-2.0-OpenSSH_8.9 OpenBSD",
			expectOS:      true,
			expectOSValue: "OpenBSD",
		},
		{
			name:          "CentOS detection",
			banner:        "SSH-2.0-OpenSSH_7.4 CentOS-7",
			expectOS:      true,
			expectOSValue: "CentOS Linux",
		},
		{
			name:          "Fedora detection",
			banner:        "SSH-2.0-OpenSSH_9.0p1 Fedora-35",
			expectOS:      true,
			expectOSValue: "Fedora Linux",
		},
		{
			name:          "Raspbian detection",
			banner:        "SSH-2.0-OpenSSH_7.9p1 Raspbian-10",
			expectOS:      true,
			expectOSValue: "Raspbian (Raspberry Pi)",
		},
		{
			name:             "Old OpenSSH version",
			banner:           "SSH-2.0-OpenSSH_6.6.1",
			expectVulnerable: true,
		},
		{
			name:           "Dropbear detection",
			banner:         "SSH-2.0-dropbear_2019.78",
			expectDropbear: true,
		},
		{
			name:        "SSH v1 protocol",
			banner:      "SSH-1.99-OpenSSH_3.9",
			expectSSHv1: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scanner := NewSSHScanner(nil)
			result := NewScanResult("ssh", 22)
			result.Banner = tt.banner

			scanner.analyzeBanner(result)

			if tt.expectOS {
				os := result.GetMetadata("detected_os")
				if os == nil {
					t.Error("expected OS to be detected")
				} else if os.(string) != tt.expectOSValue {
					t.Errorf("expected OS %q, got %q", tt.expectOSValue, os)
				}
			}

			if tt.expectVulnerable {
				hasOutdated := false
				for _, f := range result.Findings {
					if strings.Contains(f.Title, "Outdated") {
						hasOutdated = true
						break
					}
				}
				if !hasOutdated {
					t.Error("expected outdated version finding")
				}
			}

			if tt.expectDropbear {
				server := result.GetMetadata("ssh_server")
				if server == nil || server.(string) != "Dropbear" {
					t.Error("expected Dropbear to be detected")
				}
			}

			if tt.expectSSHv1 {
				hasSSHv1 := false
				for _, f := range result.Findings {
					if strings.Contains(f.Title, "SSH Protocol Version 1") {
						hasSSHv1 = true
						break
					}
				}
				if !hasSSHv1 {
					t.Error("expected SSH v1 finding")
				}
			}
		})
	}
}

// TestFTPScanner tests FTP scanning functionality.
func TestFTPScanner(t *testing.T) {
	t.Parallel()

	t.Run("creates scanner with defaults", func(t *testing.T) {
		t.Parallel()

		scanner := NewFTPScanner(nil)

		if scanner.Protocol() != "ftp" {
			t.Errorf("expected protocol 'ftp', got %q", scanner.Protocol())
		}
		if scanner.DefaultPort() != 21 {
			t.Errorf("expected port 21, got %d", scanner.DefaultPort())
		}
	})

	t.Run("WithFTPTimeout sets timeout", func(t *testing.T) {
		t.Parallel()

		scanner := NewFTPScanner(nil, WithFTPTimeout(15))

		if scanner.timeout != 15 {
			t.Errorf("expected timeout 15, got %v", scanner.timeout)
		}
	})
}

// TestSMTPScanner tests SMTP scanning functionality.
func TestSMTPScanner(t *testing.T) {
	t.Parallel()

	t.Run("creates scanner with defaults", func(t *testing.T) {
		t.Parallel()

		scanner := NewSMTPScanner(nil)

		if scanner.Protocol() != "smtp" {
			t.Errorf("expected protocol 'smtp', got %q", scanner.Protocol())
		}
		if scanner.DefaultPort() != 25 {
			t.Errorf("expected port 25, got %d", scanner.DefaultPort())
		}
	})

	t.Run("WithSMTPTimeout sets timeout", func(t *testing.T) {
		t.Parallel()

		scanner := NewSMTPScanner(nil, WithSMTPTimeout(20))

		if scanner.timeout != 20 {
			t.Errorf("expected timeout 20, got %v", scanner.timeout)
		}
	})
}

// TestFinding tests the Finding struct.
func TestFinding(t *testing.T) {
	t.Parallel()

	finding := Finding{
		Title:       "Test Finding",
		Description: "Test description",
		Severity:    model.SeverityHigh,
		Value:       "test value",
		Location:    "test location",
		Category:    "test category",
		Type:        "test_type",
	}

	if finding.Title != "Test Finding" {
		t.Errorf("unexpected Title: %s", finding.Title)
	}
	if finding.Severity != model.SeverityHigh {
		t.Errorf("unexpected Severity: %v", finding.Severity)
	}
}

// TestMongoDBScanner tests MongoDB scanner creation.
func TestMongoDBScanner(t *testing.T) {
	t.Parallel()

	t.Run("creates scanner with defaults", func(t *testing.T) {
		t.Parallel()

		scanner := NewMongoDBScanner(nil)

		if scanner.Protocol() != "mongodb" {
			t.Errorf("expected protocol 'mongodb', got %q", scanner.Protocol())
		}
		if scanner.DefaultPort() != 27017 {
			t.Errorf("expected port 27017, got %d", scanner.DefaultPort())
		}
	})
}

// TestRedisScanner tests Redis scanner creation.
func TestRedisScanner(t *testing.T) {
	t.Parallel()

	t.Run("creates scanner with defaults", func(t *testing.T) {
		t.Parallel()

		scanner := NewRedisScanner(nil)

		if scanner.Protocol() != "redis" {
			t.Errorf("expected protocol 'redis', got %q", scanner.Protocol())
		}
		if scanner.DefaultPort() != 6379 {
			t.Errorf("expected port 6379, got %d", scanner.DefaultPort())
		}
	})
}

// TestPostgreSQLScanner tests PostgreSQL scanner creation.
func TestPostgreSQLScanner(t *testing.T) {
	t.Parallel()

	t.Run("creates scanner with defaults", func(t *testing.T) {
		t.Parallel()

		scanner := NewPostgreSQLScanner(nil)

		if scanner.Protocol() != "postgresql" {
			t.Errorf("expected protocol 'postgresql', got %q", scanner.Protocol())
		}
		if scanner.DefaultPort() != 5432 {
			t.Errorf("expected port 5432, got %d", scanner.DefaultPort())
		}
	})
}

// TestMySQLScanner tests MySQL scanner creation.
func TestMySQLScanner(t *testing.T) {
	t.Parallel()

	t.Run("creates scanner with defaults", func(t *testing.T) {
		t.Parallel()

		scanner := NewMySQLScanner(nil)

		if scanner.Protocol() != "mysql" {
			t.Errorf("expected protocol 'mysql', got %q", scanner.Protocol())
		}
		if scanner.DefaultPort() != 3306 {
			t.Errorf("expected port 3306, got %d", scanner.DefaultPort())
		}
	})
}

// TestFTPBannerAnalysis tests FTP banner analysis functionality.
func TestFTPBannerAnalysis(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		banner           string
		expectServerType string
		expectHostname   bool
		expectPath       bool
	}{
		{
			name:             "vsFTPd detection",
			banner:           "220 Welcome to vsFTPd 3.0.3",
			expectServerType: "vsFTPd",
		},
		{
			name:             "ProFTPD detection",
			banner:           "220 ProFTPD Server ready",
			expectServerType: "ProFTPD",
		},
		{
			name:             "Pure-FTPd detection",
			banner:           "220-Welcome to Pure-FTPd",
			expectServerType: "Pure-FTPd",
		},
		{
			name:             "FileZilla detection",
			banner:           "220 FileZilla Server 0.9.60",
			expectServerType: "FileZilla Server",
		},
		{
			name:             "Microsoft IIS FTP detection",
			banner:           "220 Microsoft FTP Service",
			expectServerType: "Microsoft IIS FTP",
		},
		{
			name:           "hostname leak detection",
			banner:         "220 Welcome to server.example.com FTP",
			expectHostname: true,
		},
		{
			name:       "path leak detection",
			banner:     "220 FTP server /var/ftp ready",
			expectPath: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scanner := NewFTPScanner(nil)
			result := NewScanResult("ftp", 21)
			result.Banner = tt.banner

			scanner.analyzeBanner(result)

			if tt.expectServerType != "" {
				server := result.GetMetadata("ftp_server")
				if server == nil {
					t.Error("expected server type to be detected")
				} else if server.(string) != tt.expectServerType {
					t.Errorf("expected server type %q, got %q", tt.expectServerType, server)
				}
			}

			if tt.expectHostname {
				hasHostnameFinding := false
				for _, f := range result.Findings {
					if strings.Contains(f.Title, "Hostname") {
						hasHostnameFinding = true
						break
					}
				}
				if !hasHostnameFinding {
					t.Error("expected hostname leak finding")
				}
			}

			if tt.expectPath {
				hasPathFinding := false
				for _, f := range result.Findings {
					if strings.Contains(f.Title, "File Path") {
						hasPathFinding = true
						break
					}
				}
				if !hasPathFinding {
					t.Error("expected file path finding")
				}
			}
		})
	}
}

// TestSMTPBannerAnalysis tests SMTP banner analysis functionality.
func TestSMTPBannerAnalysis(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		banner           string
		expectServerType string
		expectHostname   bool
		expectESMTP      bool
	}{
		{
			name:             "Postfix detection",
			banner:           "220 mail.example.com ESMTP Postfix",
			expectServerType: "Postfix",
			expectESMTP:      true,
		},
		{
			name:             "Exim detection",
			banner:           "220 server.example.com ESMTP Exim 4.94",
			expectServerType: "Exim",
			expectESMTP:      true,
		},
		{
			name:             "Sendmail detection",
			banner:           "220 localhost Sendmail 8.15.2 ready",
			expectServerType: "Sendmail",
		},
		{
			name:             "Microsoft Exchange detection",
			banner:           "220 mail.example.com Microsoft ESMTP",
			expectServerType: "Microsoft Exchange",
			expectESMTP:      true,
		},
		{
			name:             "Dovecot detection",
			banner:           "220 Dovecot ready",
			expectServerType: "Dovecot",
		},
		{
			name:             "Zimbra detection",
			banner:           "220 mail.zimbra.example.com ESMTP Zimbra",
			expectServerType: "Zimbra",
			expectESMTP:      true,
		},
		{
			name:           "hostname leak detection",
			banner:         "220 server.clearnet.example.com ESMTP ready",
			expectHostname: true,
			expectESMTP:    true,
		},
		{
			name:   "onion address in hostname - no leak",
			banner: "220 abc123xyz.onion ESMTP ready",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scanner := NewSMTPScanner(nil)
			result := NewScanResult("smtp", 25)
			result.Banner = tt.banner

			scanner.analyzeBanner(result)

			if tt.expectServerType != "" {
				server := result.GetMetadata("smtp_server")
				if server == nil {
					t.Error("expected server type to be detected")
				} else if server.(string) != tt.expectServerType {
					t.Errorf("expected server type %q, got %q", tt.expectServerType, server)
				}
			}

			if tt.expectHostname {
				hasHostnameFinding := false
				for _, f := range result.Findings {
					if strings.Contains(f.Title, "Reveals Hostname") {
						hasHostnameFinding = true
						break
					}
				}
				if !hasHostnameFinding {
					t.Error("expected hostname leak finding")
				}
			}

			if tt.expectESMTP {
				esmtp := result.GetMetadata("esmtp")
				if esmtp == nil || esmtp.(bool) != true {
					t.Error("expected ESMTP to be detected")
				}
			}
		})
	}
}

// TestHTTPScannerAdditionalOptions tests additional HTTP scanner options.
func TestHTTPScannerAdditionalOptions(t *testing.T) {
	t.Parallel()

	t.Run("WithHTTPTimeout sets timeout", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient, WithHTTPTimeout(60))
		if scanner.timeout != 60 {
			t.Errorf("expected 60, got %v", scanner.timeout)
		}
	})

	t.Run("WithFollowRedirects sets redirect behavior", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient, WithFollowRedirects(false))
		if scanner.followRedirects {
			t.Error("expected followRedirects to be false")
		}
	})
}

// TestHTTPScannerSecurityHeaders tests detection of various security headers.
func TestHTTPScannerSecurityHeaders(t *testing.T) {
	t.Parallel()

	t.Run("detects X-Frame-Options header", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// Missing X-Frame-Options
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		scanner := NewHTTPScanner(server.Client())
		ctx := context.Background()

		result, err := scanner.Scan(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		hasFrameOptionsFinding := false
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "X-Frame-Options") {
				hasFrameOptionsFinding = true
				break
			}
		}
		if !hasFrameOptionsFinding {
			t.Error("expected finding about missing X-Frame-Options header")
		}
	})

	t.Run("detects X-Content-Type-Options header", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// Missing X-Content-Type-Options
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		scanner := NewHTTPScanner(server.Client())
		ctx := context.Background()

		result, err := scanner.Scan(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		hasContentTypeFinding := false
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "X-Content-Type-Options") {
				hasContentTypeFinding = true
				break
			}
		}
		if !hasContentTypeFinding {
			t.Error("expected finding about missing X-Content-Type-Options header")
		}
	})

	t.Run("detects X-Powered-By disclosure", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-Powered-By", "PHP/8.0")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		scanner := NewHTTPScanner(server.Client())
		ctx := context.Background()

		result, err := scanner.Scan(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		hasPoweredByFinding := false
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "X-Powered-By") {
				hasPoweredByFinding = true
				break
			}
		}
		if !hasPoweredByFinding {
			t.Error("expected finding about X-Powered-By header")
		}
	})
}

// TestScanResultNilHandling tests nil handling in ScanResult methods.
func TestScanResultNilHandling(t *testing.T) {
	t.Parallel()

	t.Run("AddFinding with nil findings slice", func(t *testing.T) {
		t.Parallel()

		result := &ScanResult{
			Protocol: "test",
			Findings: nil,
		}
		result.AddFinding(Finding{Title: "Test"})

		if len(result.Findings) != 1 {
			t.Errorf("expected 1 finding, got %d", len(result.Findings))
		}
	})

	t.Run("SetMetadata with nil metadata map", func(t *testing.T) {
		t.Parallel()

		result := &ScanResult{
			Protocol: "test",
			Metadata: nil,
		}
		result.SetMetadata("key", "value")

		if result.Metadata["key"] != "value" {
			t.Error("expected metadata to be set")
		}
	})

	t.Run("GetMetadata with nil metadata map", func(t *testing.T) {
		t.Parallel()

		result := &ScanResult{
			Protocol: "test",
			Metadata: nil,
		}

		got := result.GetMetadata("key")
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
}

// TestHTTPScannerAdditional tests additional HTTP scanning scenarios.
func TestHTTPScannerAdditional(t *testing.T) {
	t.Parallel()

	t.Run("detects HSTS header", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		scanner := NewHTTPScanner(server.Client())
		ctx := context.Background()

		result, err := scanner.Scan(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// HSTS should not create a finding for non-onion sites
		if result.Headers.Get("Strict-Transport-Security") == "" {
			t.Error("expected HSTS header to be captured")
		}
	})

	t.Run("handles missing server header", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		scanner := NewHTTPScanner(server.Client())
		ctx := context.Background()

		result, err := scanner.Scan(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Banner != "" {
			t.Errorf("expected empty banner, got %q", result.Banner)
		}
	})

	t.Run("WithHTTPTimeout sets timeout", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient, WithHTTPTimeout(30))
		if scanner.timeout != 30 {
			t.Errorf("expected timeout 30, got %v", scanner.timeout)
		}
	})

	t.Run("WithFollowRedirects sets follow redirects", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient, WithFollowRedirects(false))
		if scanner.followRedirects {
			t.Error("expected followRedirects to be false")
		}
	})

	t.Run("detects Apache version disclosure", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Server", "Apache/2.4.52 (Ubuntu)")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		scanner := NewHTTPScanner(server.Client())
		ctx := context.Background()

		result, err := scanner.Scan(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		hasVersionFinding := false
		for _, f := range result.Findings {
			if f.Type == "server_version" || strings.Contains(f.Title, "Version") {
				hasVersionFinding = true
				break
			}
		}
		if !hasVersionFinding {
			t.Error("expected server version finding")
		}
	})

	t.Run("detects ETag with inode leak", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// Apache-style ETag with inode number (not prefixed with W/)
			w.Header().Set("ETag", `"123456-789-abc"`)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		scanner := NewHTTPScanner(server.Client())
		ctx := context.Background()

		result, err := scanner.Scan(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		hasETagFinding := false
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "ETag") {
				hasETagFinding = true
				break
			}
		}
		if !hasETagFinding {
			t.Error("expected ETag inode leak finding")
		}
	})
}

// TestCertificateInfo tests the CertificateInfo struct.
func TestCertificateInfo(t *testing.T) {
	t.Parallel()

	t.Run("struct fields are accessible", func(t *testing.T) {
		t.Parallel()

		cert := CertificateInfo{
			Subject:             "CN=example.com",
			Issuer:              "CN=Let's Encrypt",
			NotBefore:           "2023-01-01",
			NotAfter:            "2024-01-01",
			SerialNumber:        "123456",
			CommonName:          "example.com",
			SANs:                []string{"www.example.com"},
			DNSNames:            []string{"example.com", "www.example.com"},
			EmailAddresses:      []string{"admin@example.com"},
			IssuingOrganization: "Let's Encrypt",
		}

		if cert.Subject != "CN=example.com" {
			t.Errorf("unexpected Subject: %s", cert.Subject)
		}
		if len(cert.DNSNames) != 2 {
			t.Errorf("expected 2 DNS names, got %d", len(cert.DNSNames))
		}
		if len(cert.EmailAddresses) != 1 {
			t.Errorf("expected 1 email, got %d", len(cert.EmailAddresses))
		}
	})
}

// TestHTTPScannerProtocolAndPort tests Protocol and DefaultPort methods.
func TestHTTPScannerProtocolAndPort(t *testing.T) {
	t.Parallel()

	t.Run("Protocol returns http", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		if scanner.Protocol() != "http" {
			t.Errorf("expected 'http', got %q", scanner.Protocol())
		}
	})

	t.Run("DefaultPort returns 80", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		if scanner.DefaultPort() != 80 {
			t.Errorf("expected 80, got %d", scanner.DefaultPort())
		}
	})
}

// TestDatabaseScanners tests database scanner constructors.
func TestDatabaseScanners(t *testing.T) {
	t.Parallel()

	t.Run("MongoDB scanner", func(t *testing.T) {
		t.Parallel()

		scanner := NewMongoDBScanner(nil)
		if scanner.Protocol() != "mongodb" {
			t.Errorf("expected 'mongodb', got %q", scanner.Protocol())
		}
		if scanner.DefaultPort() != 27017 {
			t.Errorf("expected 27017, got %d", scanner.DefaultPort())
		}
	})

	t.Run("Redis scanner", func(t *testing.T) {
		t.Parallel()

		scanner := NewRedisScanner(nil)
		if scanner.Protocol() != "redis" {
			t.Errorf("expected 'redis', got %q", scanner.Protocol())
		}
		if scanner.DefaultPort() != 6379 {
			t.Errorf("expected 6379, got %d", scanner.DefaultPort())
		}
	})

	t.Run("PostgreSQL scanner", func(t *testing.T) {
		t.Parallel()

		scanner := NewPostgreSQLScanner(nil)
		if scanner.Protocol() != "postgresql" {
			t.Errorf("expected 'postgresql', got %q", scanner.Protocol())
		}
		if scanner.DefaultPort() != 5432 {
			t.Errorf("expected 5432, got %d", scanner.DefaultPort())
		}
	})

	t.Run("MySQL scanner", func(t *testing.T) {
		t.Parallel()

		scanner := NewMySQLScanner(nil)
		if scanner.Protocol() != "mysql" {
			t.Errorf("expected 'mysql', got %q", scanner.Protocol())
		}
		if scanner.DefaultPort() != 3306 {
			t.Errorf("expected 3306, got %d", scanner.DefaultPort())
		}
	})
}

// TestHTTPScannerAnalyzeHeaders tests header analysis.
func TestHTTPScannerAnalyzeHeaders(t *testing.T) {
	t.Parallel()

	t.Run("detects server version disclosure", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("http", 80)
		result.Headers.Set("Server", "Apache/2.4.41 (Ubuntu)")

		scanner.analyzeHeaders(result)

		found := false
		for _, f := range result.Findings {
			if f.Title == "Server Version Disclosed" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find server version disclosure finding")
		}
	})

	t.Run("does not flag generic server header", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("http", 80)
		result.Headers.Set("Server", "Apache")

		scanner.analyzeHeaders(result)

		for _, f := range result.Findings {
			if f.Title == "Server Version Disclosed" {
				t.Error("should not flag generic server header without version")
			}
		}
	})

	t.Run("detects X-Powered-By header", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("http", 80)
		result.Headers.Set("X-Powered-By", "PHP/8.1.0")

		scanner.analyzeHeaders(result)

		found := false
		for _, f := range result.Findings {
			if f.Title == "X-Powered-By Header Present" {
				found = true
				if f.Value != "PHP/8.1.0" {
					t.Errorf("expected value 'PHP/8.1.0', got %q", f.Value)
				}
				break
			}
		}
		if !found {
			t.Error("expected to find X-Powered-By finding")
		}
	})

	t.Run("detects ETag with potential inode leak", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("http", 80)
		// Apache-style ETag with inode-mtime-size format
		result.Headers.Set("ETag", `"1234-5678-9abc"`)

		scanner.analyzeHeaders(result)

		found := false
		for _, f := range result.Findings {
			if f.Title == "ETag May Leak Inode Number" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find ETag inode leak finding")
		}
	})

	t.Run("does not flag weak ETag", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("http", 80)
		// Weak ETag should not trigger the finding
		result.Headers.Set("ETag", `W/"abc-def"`)

		scanner.analyzeHeaders(result)

		for _, f := range result.Findings {
			if f.Title == "ETag May Leak Inode Number" {
				t.Error("should not flag weak ETags")
			}
		}
	})

	t.Run("does not flag ETag without dashes", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("http", 80)
		result.Headers.Set("ETag", `"abcdef1234567890"`)

		scanner.analyzeHeaders(result)

		for _, f := range result.Findings {
			if f.Title == "ETag May Leak Inode Number" {
				t.Error("should not flag ETags without dashes")
			}
		}
	})
}

// TestHTTPScannerModStatusCheck tests mod_status detection.
func TestHTTPScannerModStatusCheck(t *testing.T) {
	t.Parallel()

	t.Run("returns false when not Apache", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("http", 80)
		result.Headers.Set("Server", "nginx/1.20.0")

		isModStatus := scanner.checkModStatus(result)
		if isModStatus {
			t.Error("should return false for non-Apache server")
		}
	})

	t.Run("returns false when Apache but no target_url", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("http", 80)
		result.Headers.Set("Server", "Apache/2.4.41")
		// No target_url metadata

		isModStatus := scanner.checkModStatus(result)
		if isModStatus {
			t.Error("should return false when target_url is not set")
		}
	})

	t.Run("returns false when nil client", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(nil)
		result := NewScanResult("http", 80)
		result.Headers.Set("Server", "Apache/2.4.41")
		result.SetMetadata("target_url", "http://example.com")

		isModStatus := scanner.checkModStatus(result)
		if isModStatus {
			t.Error("should return false when client is nil")
		}
	})

	t.Run("returns true when mod_status is exposed", func(t *testing.T) {
		t.Parallel()

		// Create a test server that simulates Apache with mod_status
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/server-status" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<html>
<head><title>Apache Status</title></head>
<body>
<h1>Apache Server Status for localhost</h1>
Server Version: Apache/2.4.41 (Ubuntu)
Current Time: Saturday, 30-Nov-2024 12:00:00 UTC
Restart Time: Saturday, 30-Nov-2024 10:00:00 UTC
Total accesses: 12345
CPU Usage: 0.5%
</body>
</html>`))
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		scanner := NewHTTPScanner(server.Client())
		result := NewScanResult("http", 80)
		result.Headers.Set("Server", "Apache/2.4.41")
		result.SetMetadata("target_url", server.URL)

		isModStatus := scanner.checkModStatus(result)
		if !isModStatus {
			t.Error("should return true when mod_status is accessible")
		}

		// Verify metadata was stored
		content := result.GetMetadata("mod_status_content")
		if content == nil {
			t.Error("expected mod_status_content to be stored")
		}
		statusURL := result.GetMetadata("mod_status_url")
		if statusURL == nil {
			t.Error("expected mod_status_url to be stored")
		}
	})

	t.Run("returns false when server-status returns 404", func(t *testing.T) {
		t.Parallel()

		// Create a test server that returns 404 for /server-status
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		scanner := NewHTTPScanner(server.Client())
		result := NewScanResult("http", 80)
		result.Headers.Set("Server", "Apache/2.4.41")
		result.SetMetadata("target_url", server.URL)

		isModStatus := scanner.checkModStatus(result)
		if isModStatus {
			t.Error("should return false when server-status is not accessible")
		}
	})

	t.Run("returns false when response does not contain mod_status indicators", func(t *testing.T) {
		t.Parallel()

		// Create a test server that returns a generic page
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>Just a normal page</body></html>"))
		}))
		defer server.Close()

		scanner := NewHTTPScanner(server.Client())
		result := NewScanResult("http", 80)
		result.Headers.Set("Server", "Apache/2.4.41")
		result.SetMetadata("target_url", server.URL)

		isModStatus := scanner.checkModStatus(result)
		if isModStatus {
			t.Error("should return false when response doesn't contain mod_status indicators")
		}
	})
}

// TestHTTPScannerExtractTLSInfo tests TLS information extraction.
func TestHTTPScannerExtractTLSInfo(t *testing.T) {
	t.Parallel()

	t.Run("extracts TLS 1.0 version", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("https", 443)

		state := &tls.ConnectionState{
			Version: tls.VersionTLS10,
		}

		scanner.extractTLSInfo(result, state)

		if !result.TLS {
			t.Error("expected TLS to be true")
		}
		if result.TLSVersion != "TLS 1.0" {
			t.Errorf("expected TLS 1.0, got %q", result.TLSVersion)
		}
	})

	t.Run("extracts TLS 1.1 version", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("https", 443)

		state := &tls.ConnectionState{
			Version: tls.VersionTLS11,
		}

		scanner.extractTLSInfo(result, state)

		if result.TLSVersion != "TLS 1.1" {
			t.Errorf("expected TLS 1.1, got %q", result.TLSVersion)
		}
	})

	t.Run("extracts TLS 1.2 version", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("https", 443)

		state := &tls.ConnectionState{
			Version: tls.VersionTLS12,
		}

		scanner.extractTLSInfo(result, state)

		if result.TLSVersion != "TLS 1.2" {
			t.Errorf("expected TLS 1.2, got %q", result.TLSVersion)
		}
	})

	t.Run("extracts TLS 1.3 version", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("https", 443)

		state := &tls.ConnectionState{
			Version: tls.VersionTLS13,
		}

		scanner.extractTLSInfo(result, state)

		if result.TLSVersion != "TLS 1.3" {
			t.Errorf("expected TLS 1.3, got %q", result.TLSVersion)
		}
	})

	t.Run("handles unknown TLS version", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("https", 443)

		state := &tls.ConnectionState{
			Version: 0x9999, // Unknown version
		}

		scanner.extractTLSInfo(result, state)

		if result.TLSVersion != "Unknown" {
			t.Errorf("expected Unknown, got %q", result.TLSVersion)
		}
	})

	t.Run("extracts certificate information", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("https", 443)

		cert := &x509.Certificate{
			Subject: pkix.Name{
				CommonName:   "example.onion",
				Organization: []string{"Test Org"},
			},
			Issuer: pkix.Name{
				CommonName:   "Test CA",
				Organization: []string{"Test CA Org"},
			},
			NotBefore:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			SerialNumber:   big.NewInt(12345),
			DNSNames:       []string{"example.onion"},
			EmailAddresses: []string{},
		}

		state := &tls.ConnectionState{
			Version:          tls.VersionTLS13,
			PeerCertificates: []*x509.Certificate{cert},
		}

		scanner.extractTLSInfo(result, state)

		if result.Certificate == nil {
			t.Fatal("expected certificate info to be extracted")
		}
		if !strings.Contains(result.Certificate.Subject, "example.onion") {
			t.Errorf("expected subject to contain example.onion, got %q", result.Certificate.Subject)
		}
		if result.Certificate.SerialNumber != "12345" {
			t.Errorf("expected serial 12345, got %q", result.Certificate.SerialNumber)
		}
	})
}

// TestHTTPScannerAnalyzeCertificate tests certificate analysis for identity leaks.
func TestHTTPScannerAnalyzeCertificate(t *testing.T) {
	t.Parallel()

	t.Run("returns early when certificate is nil", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("https", 443)
		result.Certificate = nil

		// Should not panic
		scanner.analyzeCertificate(result)

		if len(result.Findings) != 0 {
			t.Error("expected no findings for nil certificate")
		}
	})

	t.Run("detects clearnet domain in DNS names", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("https", 443)
		result.Certificate = &CertificateInfo{
			DNSNames: []string{"example.com", "www.example.com"},
		}

		scanner.analyzeCertificate(result)

		hasClearnetFinding := false
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "Clearnet Domain") {
				hasClearnetFinding = true
				break
			}
		}
		if !hasClearnetFinding {
			t.Error("expected finding about clearnet domain in certificate")
		}
	})

	t.Run("skips onion addresses in DNS names", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("https", 443)
		result.Certificate = &CertificateInfo{
			DNSNames: []string{"example.onion", "test.onion"},
		}

		scanner.analyzeCertificate(result)

		hasClearnetFinding := false
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "Clearnet Domain") {
				hasClearnetFinding = true
				break
			}
		}
		if hasClearnetFinding {
			t.Error("should not flag onion addresses as clearnet domains")
		}
	})

	t.Run("detects email address in certificate", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("https", 443)
		result.Certificate = &CertificateInfo{
			EmailAddresses: []string{"admin@example.com"},
		}

		scanner.analyzeCertificate(result)

		hasEmailFinding := false
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "Email Address") {
				hasEmailFinding = true
				if f.Severity != model.SeverityCritical {
					t.Errorf("expected critical severity, got %v", f.Severity)
				}
				break
			}
		}
		if !hasEmailFinding {
			t.Error("expected finding about email address in certificate")
		}
	})

	t.Run("detects multiple email addresses", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("https", 443)
		result.Certificate = &CertificateInfo{
			EmailAddresses: []string{"admin@example.com", "support@example.com"},
		}

		scanner.analyzeCertificate(result)

		emailCount := 0
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "Email Address") {
				emailCount++
			}
		}
		if emailCount != 2 {
			t.Errorf("expected 2 email findings, got %d", emailCount)
		}
	})
}

// TestHTTPScannerCheckSecurityHeaders tests security header checks.
func TestHTTPScannerCheckSecurityHeaders(t *testing.T) {
	t.Parallel()

	t.Run("detects missing X-Frame-Options", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("http", 80)
		// No X-Frame-Options header

		scanner.checkSecurityHeaders(result)

		hasFrameOptionsFinding := false
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "X-Frame-Options") {
				hasFrameOptionsFinding = true
				break
			}
		}
		if !hasFrameOptionsFinding {
			t.Error("expected finding about missing X-Frame-Options")
		}
	})

	t.Run("detects missing X-Content-Type-Options", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("http", 80)
		// No X-Content-Type-Options header

		scanner.checkSecurityHeaders(result)

		hasContentTypeFinding := false
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "X-Content-Type-Options") {
				hasContentTypeFinding = true
				break
			}
		}
		if !hasContentTypeFinding {
			t.Error("expected finding about missing X-Content-Type-Options")
		}
	})

	t.Run("no findings when security headers are present", func(t *testing.T) {
		t.Parallel()

		scanner := NewHTTPScanner(http.DefaultClient)
		result := NewScanResult("http", 80)
		result.Headers.Set("X-Frame-Options", "DENY")
		result.Headers.Set("X-Content-Type-Options", "nosniff")

		scanner.checkSecurityHeaders(result)

		for _, f := range result.Findings {
			if strings.Contains(f.Title, "X-Frame-Options") || strings.Contains(f.Title, "X-Content-Type-Options") {
				t.Errorf("unexpected finding when headers are present: %s", f.Title)
			}
		}
	})
}

// TestSMTPExtractHostname tests SMTP hostname extraction from banners.
func TestSMTPExtractHostname(t *testing.T) {
	t.Parallel()

	t.Run("extracts hostname from clearnet domain", func(t *testing.T) {
		t.Parallel()

		scanner := NewSMTPScanner(nil)
		result := NewScanResult("smtp", 25)
		result.Banner = "220 mail.example.com ESMTP Postfix"

		scanner.extractHostname(result)

		hostname := result.GetMetadata("smtp_hostname")
		if hostname == nil || hostname.(string) != "mail.example.com" {
			t.Errorf("expected hostname mail.example.com, got %v", hostname)
		}

		// Should have a finding for clearnet hostname
		hasHostnameFinding := false
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "Reveals Hostname") {
				hasHostnameFinding = true
				break
			}
		}
		if !hasHostnameFinding {
			t.Error("expected finding about hostname leak")
		}
	})

	t.Run("extracts onion hostname without finding", func(t *testing.T) {
		t.Parallel()

		scanner := NewSMTPScanner(nil)
		result := NewScanResult("smtp", 25)
		result.Banner = "220 abc123xyz.onion ESMTP ready"

		scanner.extractHostname(result)

		hostname := result.GetMetadata("smtp_hostname")
		if hostname == nil || hostname.(string) != "abc123xyz.onion" {
			t.Errorf("expected onion hostname, got %v", hostname)
		}

		// Should NOT have a finding for onion hostname
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "Reveals Hostname") {
				t.Error("should not flag onion hostname as a leak")
			}
		}
	})

	t.Run("handles banner with 220- prefix", func(t *testing.T) {
		t.Parallel()

		scanner := NewSMTPScanner(nil)
		result := NewScanResult("smtp", 25)
		result.Banner = "220-mail.server.net Welcome"

		scanner.extractHostname(result)

		hostname := result.GetMetadata("smtp_hostname")
		if hostname == nil || hostname.(string) != "mail.server.net" {
			t.Errorf("expected hostname mail.server.net, got %v", hostname)
		}
	})

	t.Run("skips non-domain entries", func(t *testing.T) {
		t.Parallel()

		scanner := NewSMTPScanner(nil)
		result := NewScanResult("smtp", 25)
		result.Banner = "220 localhost ESMTP"

		scanner.extractHostname(result)

		// Should not have hostname finding for "localhost" (no dot)
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "Reveals Hostname") {
				t.Error("should not flag localhost as hostname leak")
			}
		}
	})

	t.Run("skips email addresses", func(t *testing.T) {
		t.Parallel()

		scanner := NewSMTPScanner(nil)
		result := NewScanResult("smtp", 25)
		result.Banner = "220 user@example.com ESMTP"

		scanner.extractHostname(result)

		// Should not flag email addresses as hostname leaks
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "Reveals Hostname") && f.Value == "user@example.com" {
				t.Error("should not flag email address as hostname leak")
			}
		}
	})
}

// TestSMTPCheckBannerLeaks tests SMTP banner leak detection.
func TestSMTPCheckBannerLeaks(t *testing.T) {
	t.Parallel()

	t.Run("detects ESMTP support", func(t *testing.T) {
		t.Parallel()

		scanner := NewSMTPScanner(nil)
		result := NewScanResult("smtp", 25)
		result.Banner = "220 server ESMTP ready"

		scanner.checkBannerLeaks(result)

		esmtp := result.GetMetadata("esmtp")
		if esmtp == nil || esmtp.(bool) != true {
			t.Error("expected ESMTP to be detected")
		}
	})

	t.Run("detects version disclosure", func(t *testing.T) {
		t.Parallel()

		scanner := NewSMTPScanner(nil)
		result := NewScanResult("smtp", 25)
		result.Banner = "220 mail.example.com Postfix 3.4.14"

		scanner.checkBannerLeaks(result)

		hasVersionFinding := false
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "Version Disclosed") {
				hasVersionFinding = true
				break
			}
		}
		if !hasVersionFinding {
			t.Error("expected version disclosure finding")
		}
	})
}

// TestFTPCheckBannerLeaks tests FTP banner leak detection.
func TestFTPCheckBannerLeaks(t *testing.T) {
	t.Parallel()

	t.Run("detects hostname in welcome message", func(t *testing.T) {
		t.Parallel()

		scanner := NewFTPScanner(nil)
		result := NewScanResult("ftp", 21)
		result.Banner = "220 Welcome to ftp.example.com FTP server"

		scanner.checkBannerLeaks(result)

		hasHostnameFinding := false
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "Hostname") {
				hasHostnameFinding = true
				break
			}
		}
		if !hasHostnameFinding {
			t.Error("expected finding about hostname in welcome message")
		}
	})

	t.Run("detects file path in banner", func(t *testing.T) {
		t.Parallel()

		scanner := NewFTPScanner(nil)
		result := NewScanResult("ftp", 21)
		result.Banner = "220 FTP server /var/ftp ready"

		scanner.checkBannerLeaks(result)

		hasPathFinding := false
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "File Path") {
				hasPathFinding = true
				break
			}
		}
		if !hasPathFinding {
			t.Error("expected finding about file path in banner")
		}
	})

	t.Run("detects Windows path in banner", func(t *testing.T) {
		t.Parallel()

		scanner := NewFTPScanner(nil)
		result := NewScanResult("ftp", 21)
		result.Banner = "220 FTP server C:\\FTP ready"

		scanner.checkBannerLeaks(result)

		hasPathFinding := false
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "File Path") {
				hasPathFinding = true
				break
			}
		}
		if !hasPathFinding {
			t.Error("expected finding about Windows file path in banner")
		}
	})

	t.Run("no findings for clean banner", func(t *testing.T) {
		t.Parallel()

		scanner := NewFTPScanner(nil)
		result := NewScanResult("ftp", 21)
		result.Banner = "220 FTP server ready"

		scanner.checkBannerLeaks(result)

		for _, f := range result.Findings {
			if strings.Contains(f.Title, "Hostname") || strings.Contains(f.Title, "Path") {
				t.Errorf("unexpected finding for clean banner: %s", f.Title)
			}
		}
	})
}

// TestHTTPScannerFullScanWithModStatus tests the full HTTP scan flow with mod_status detection.
func TestHTTPScannerFullScanWithModStatus(t *testing.T) {
	t.Parallel()

	t.Run("detects mod_status during scan", func(t *testing.T) {
		t.Parallel()

		// Create a test server that simulates Apache with mod_status
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
			if r.URL.Path == "/server-status" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<html>
<head><title>Apache Status</title></head>
<body>
<h1>Apache Server Status</h1>
Server Version: Apache/2.4.41 (Ubuntu)
Current Time: Saturday, 30-Nov-2024 12:00:00 UTC
Restart Time: Saturday, 30-Nov-2024 10:00:00 UTC
Total accesses: 12345
</body>
</html>`))
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("<html><body>Welcome</body></html>"))
			}
		}))
		defer server.Close()

		scanner := NewHTTPScanner(server.Client())
		ctx := context.Background()

		result, err := scanner.Scan(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Detected {
			t.Error("expected service to be detected")
		}

		// Check that mod_status finding was added
		hasModStatusFinding := false
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "mod_status") {
				hasModStatusFinding = true
				if f.Severity != model.SeverityHigh {
					t.Errorf("expected high severity, got %v", f.Severity)
				}
				break
			}
		}
		if !hasModStatusFinding {
			t.Error("expected finding about Apache mod_status")
		}
	})

	t.Run("no mod_status finding when not exposed", func(t *testing.T) {
		t.Parallel()

		// Create a test server that simulates Apache without mod_status
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
			if r.URL.Path == "/server-status" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("Access Denied"))
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("<html><body>Welcome</body></html>"))
			}
		}))
		defer server.Close()

		scanner := NewHTTPScanner(server.Client())
		ctx := context.Background()

		result, err := scanner.Scan(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Check that mod_status finding was NOT added
		for _, f := range result.Findings {
			if strings.Contains(f.Title, "mod_status") {
				t.Error("should not have mod_status finding when access is denied")
			}
		}
	})
}
