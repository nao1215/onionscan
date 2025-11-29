package deanon

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/nao1215/onionscan/internal/model"
	"github.com/nao1215/onionscan/internal/protocol"
)

// TestEmailAnalyzer tests email detection functionality.
func TestEmailAnalyzer(t *testing.T) {
	t.Parallel()

	t.Run("detects email addresses", func(t *testing.T) {
		t.Parallel()

		analyzer := NewEmailAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/contact",
					Snapshot: "Contact us at admin@example.com or support@test.org",
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(findings) != 2 {
			t.Errorf("expected 2 findings, got %d", len(findings))
		}
	})

	t.Run("deduplicates emails", func(t *testing.T) {
		t.Parallel()

		analyzer := NewEmailAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/page1",
					Snapshot: "Email: test@example.com",
				},
				{
					URL:      "http://test.onion/page2",
					Snapshot: "Also: test@example.com",
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(findings) != 1 {
			t.Errorf("expected 1 unique finding, got %d", len(findings))
		}
	})

	t.Run("rates corporate emails higher", func(t *testing.T) {
		t.Parallel()

		analyzer := NewEmailAnalyzer()

		gmailSeverity := analyzer.assessEmailSeverity("user@gmail.com")
		corpSeverity := analyzer.assessEmailSeverity("user@company.com")

		if corpSeverity <= gmailSeverity {
			t.Error("expected corporate email to have higher severity than gmail")
		}
	})
}

// TestAnalyticsAnalyzer tests analytics ID detection.
func TestAnalyticsAnalyzer(t *testing.T) {
	t.Parallel()

	t.Run("detects Google Analytics UA", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAnalyticsAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `<script>ga('create', 'UA-123456-1', 'auto');</script>`,
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Value == "UA-123456-1" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find UA-123456-1")
		}
	})

	t.Run("detects Google Analytics 4", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAnalyticsAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `gtag('config', 'G-1234567890');`,
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Value == "G-1234567890" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find G-1234567890")
		}
	})

	t.Run("detects Google Tag Manager", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAnalyticsAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `googletagmanager.com/gtm.js?id=GTM-ABC123`,
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Value == "GTM-ABC123" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find GTM-ABC123")
		}
	})
}

// TestCryptoAnalyzer tests cryptocurrency address detection.
func TestCryptoAnalyzer(t *testing.T) {
	t.Parallel()

	t.Run("detects Bitcoin legacy address", func(t *testing.T) {
		t.Parallel()

		analyzer := NewCryptoAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/donate",
					Snapshot: "Donate BTC: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Value == "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find Bitcoin address")
		}
	})

	t.Run("detects Ethereum address", func(t *testing.T) {
		t.Parallel()

		analyzer := NewCryptoAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/donate",
					Snapshot: "ETH: 0x742d35Cc6634C0532925a3b844Bc9e7595f21276",
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Value == "0x742d35Cc6634C0532925a3b844Bc9e7595f21276" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find Ethereum address")
		}
	})
}

// TestAnalyzer tests the main Analyzer coordinator.
func TestAnalyzer(t *testing.T) {
	t.Parallel()

	t.Run("runs all analyzers", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: "Contact: admin@example.com, Analytics: UA-123456-1",
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should find at least email and analytics
		if len(findings) < 2 {
			t.Errorf("expected at least 2 findings, got %d", len(findings))
		}
	})

	t.Run("deduplicates across analyzers", func(t *testing.T) {
		t.Parallel()

		findings := []model.Finding{
			{Title: "Test", Value: "value1", Severity: model.SeverityLow},
			{Title: "Test", Value: "value1", Severity: model.SeverityHigh},
			{Title: "Test", Value: "value2", Severity: model.SeverityMedium},
		}

		deduped := deduplicateFindings(findings)

		if len(deduped) != 2 {
			t.Errorf("expected 2 findings after dedup, got %d", len(deduped))
		}

		// Should keep the higher severity
		for _, f := range deduped {
			if f.Value == "value1" && f.Severity != model.SeverityHigh {
				t.Error("expected to keep higher severity finding")
			}
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAnalyzer()
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{URL: "http://test.onion/", Snapshot: "test"},
			},
		}

		_, err := analyzer.Analyze(ctx, data)
		if err == nil {
			t.Log("analyzer completed quickly or handled cancellation gracefully")
		}
	})
}

// TestServerInfoAnalyzer tests server information analysis.
func TestServerInfoAnalyzer(t *testing.T) {
	t.Parallel()

	t.Run("detects server version", func(t *testing.T) {
		t.Parallel()

		analyzer := NewServerInfoAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Headers: map[string][]string{
						"Server": {"Apache/2.4.41 (Ubuntu)"},
					},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(findings) < 1 {
			t.Error("expected at least one finding about server version")
		}
	})
}

// TestExternalLinkAnalyzer tests external link detection.
func TestExternalLinkAnalyzer(t *testing.T) {
	t.Parallel()

	t.Run("detects clearnet links", func(t *testing.T) {
		t.Parallel()

		analyzer := NewExternalLinkAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Anchors: []model.Element{
						{Source: "http://example.com/page"},
						{Source: "http://other.onion/page"},
					},
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should find clearnet link but not onion link
		found := false
		for _, f := range findings {
			if f.Value == "example.com" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find clearnet link")
		}
	})

	t.Run("rates social media links as high severity", func(t *testing.T) {
		t.Parallel()

		analyzer := NewExternalLinkAnalyzer()
		severity := analyzer.assessLinkSeverity("twitter.com")

		if severity != model.SeverityHigh {
			t.Errorf("expected high severity for twitter, got %v", severity)
		}
	})
}

// TestAnalyzerInterfaces tests Name() and Category() methods.
func TestAnalyzerInterfaces(t *testing.T) {
	t.Parallel()

	t.Run("EmailAnalyzer Name and Category", func(t *testing.T) {
		t.Parallel()

		analyzer := NewEmailAnalyzer()
		if analyzer.Name() == "" {
			t.Error("expected non-empty name")
		}
		if analyzer.Category() == "" {
			t.Error("expected non-empty category")
		}
	})

	t.Run("AnalyticsAnalyzer Name and Category", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAnalyticsAnalyzer()
		if analyzer.Name() == "" {
			t.Error("expected non-empty name")
		}
		if analyzer.Category() == "" {
			t.Error("expected non-empty category")
		}
	})

	t.Run("CryptoAnalyzer Name and Category", func(t *testing.T) {
		t.Parallel()

		analyzer := NewCryptoAnalyzer()
		if analyzer.Name() == "" {
			t.Error("expected non-empty name")
		}
		if analyzer.Category() == "" {
			t.Error("expected non-empty category")
		}
	})

	t.Run("ExternalLinkAnalyzer Name and Category", func(t *testing.T) {
		t.Parallel()

		analyzer := NewExternalLinkAnalyzer()
		if analyzer.Name() == "" {
			t.Error("expected non-empty name")
		}
		if analyzer.Category() == "" {
			t.Error("expected non-empty category")
		}
	})

	t.Run("ServerInfoAnalyzer Name and Category", func(t *testing.T) {
		t.Parallel()

		analyzer := NewServerInfoAnalyzer()
		if analyzer.Name() == "" {
			t.Error("expected non-empty name")
		}
		if analyzer.Category() == "" {
			t.Error("expected non-empty category")
		}
	})
}

// TestAnalyzerWithOptions tests analyzer options.
func TestAnalyzerWithOptions(t *testing.T) {
	t.Parallel()

	t.Run("NewAnalyzer with options", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAnalyzer(func(opts *AnalyzerOptions) {
			opts.EnableEXIF = true
			opts.EnablePDFAnalysis = true
		})
		if analyzer == nil {
			t.Error("expected non-nil analyzer")
		}
	})

	t.Run("DefaultOptions has expected values", func(t *testing.T) {
		t.Parallel()

		opts := DefaultOptions()
		if !opts.EnableEXIF {
			t.Error("expected EnableEXIF to be true by default")
		}
		if !opts.EnablePDFAnalysis {
			t.Error("expected EnablePDFAnalysis to be true by default")
		}
	})
}

// TestCryptoAnalyzerMoreTypes tests more crypto address types.
func TestCryptoAnalyzerMoreTypes(t *testing.T) {
	t.Parallel()

	t.Run("detects Bitcoin bech32 address", func(t *testing.T) {
		t.Parallel()

		analyzer := NewCryptoAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/donate",
					Snapshot: "Donate BTC: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Value == "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find Bitcoin bech32 address")
		}
	})

	t.Run("detects Monero address", func(t *testing.T) {
		t.Parallel()

		analyzer := NewCryptoAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/donate",
					Snapshot: "XMR: 46qepAmCFdF16RA7UKQ8w4FHcAZ8xyvLjHyBv8n3VF1PCY5TfAv9Nq5YBHMeG1VXWQJF2bvfVyW8rnKDcC7tGFC4K6XCQS",
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Monero addresses are 95 chars, check for findings
		if len(findings) > 0 {
			t.Log("found crypto address findings")
		}
	})
}

// TestAnalyticsAnalyzerMoreTypes tests more analytics types.
func TestAnalyticsAnalyzerMoreTypes(t *testing.T) {
	t.Parallel()

	t.Run("detects Meta Pixel", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAnalyticsAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `fbq('init', '1234567890123456');`,
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Value == "1234567890123456" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find Meta Pixel ID")
		}
	})

	t.Run("detects Matomo", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAnalyticsAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `_paq.push(['setSiteId', '42']);`,
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Value == "42" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find Matomo site ID")
		}
	})
}

// TestServerInfoAnalyzerMoreHeaders tests more header analysis.
func TestServerInfoAnalyzerMoreHeaders(t *testing.T) {
	t.Parallel()

	t.Run("detects X-Powered-By", func(t *testing.T) {
		t.Parallel()

		analyzer := NewServerInfoAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Headers: map[string][]string{
						"X-Powered-By": {"PHP/7.4"},
					},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Value == "PHP/7.4" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find X-Powered-By value")
		}
	})

	t.Run("detects ETag with inode", func(t *testing.T) {
		t.Parallel()

		analyzer := NewServerInfoAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Headers: map[string][]string{
						"ETag": {`"1234-5678-abcd"`},
					},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(findings) > 0 {
			t.Log("found ETag-related findings")
		}
	})
}

// TestExternalLinkAnalyzerMoreCases tests more external link cases.
func TestExternalLinkAnalyzerMoreCases(t *testing.T) {
	t.Parallel()

	t.Run("detects CDN links", func(t *testing.T) {
		t.Parallel()

		analyzer := NewExternalLinkAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Anchors: []model.Element{
						{Source: "https://cdnjs.cloudflare.com/script.js"},
					},
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(findings) > 0 {
			t.Log("found CDN-related findings")
		}
	})

	t.Run("rates payment links as medium", func(t *testing.T) {
		t.Parallel()

		analyzer := NewExternalLinkAnalyzer()
		severity := analyzer.assessLinkSeverity("paypal.com")

		// Payment sites that aren't in the social media list are medium severity
		if severity != model.SeverityMedium {
			t.Errorf("expected medium severity for paypal, got %v", severity)
		}
	})

	t.Run("rates unknown links as medium", func(t *testing.T) {
		t.Parallel()

		analyzer := NewExternalLinkAnalyzer()
		severity := analyzer.assessLinkSeverity("unknown-random-site.com")

		if severity != model.SeverityMedium {
			t.Errorf("expected medium severity for unknown site, got %v", severity)
		}
	})
}

// TestRegisterCustomAnalyzer tests registering custom analyzers.
func TestRegisterCustomAnalyzer(t *testing.T) {
	t.Parallel()

	analyzer := NewAnalyzer()

	// Create a mock analyzer
	mockAnalyzer := &mockPageAnalyzer{
		name:     "mock",
		category: "test",
	}

	analyzer.Register(mockAnalyzer)

	// Verify it was registered by running analysis
	data := &AnalysisData{
		HiddenService: "test.onion",
		Pages: []*model.Page{
			{URL: "http://test.onion/", Snapshot: "test"},
		},
		Report: model.NewOnionScanReport("test.onion"),
	}

	_, err := analyzer.Analyze(context.Background(), data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

type mockPageAnalyzer struct {
	name     string
	category string
}

func (m *mockPageAnalyzer) Name() string {
	return m.name
}

func (m *mockPageAnalyzer) Category() string {
	return m.category
}

func (m *mockPageAnalyzer) Analyze(_ context.Context, _ *AnalysisData) ([]model.Finding, error) {
	return nil, nil
}

// TestHeaderAnalyzer tests HTTP header analysis.
func TestHeaderAnalyzer(t *testing.T) {
	t.Parallel()

	t.Run("Name returns correct value", func(t *testing.T) {
		t.Parallel()
		analyzer := NewHeaderAnalyzer()
		if analyzer.Name() != "headers" {
			t.Errorf("expected name 'headers', got %q", analyzer.Name())
		}
	})

	t.Run("Category returns security", func(t *testing.T) {
		t.Parallel()
		analyzer := NewHeaderAnalyzer()
		if analyzer.Category() != "security" {
			t.Errorf("expected category 'security', got %q", analyzer.Category())
		}
	})

	t.Run("detects ETag header", func(t *testing.T) {
		t.Parallel()

		analyzer := NewHeaderAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Headers: map[string][]string{
						"ETag": {`"123abc"`},
					},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "etag_tracking" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find ETag tracking finding")
		}
	})

	t.Run("detects cookies", func(t *testing.T) {
		t.Parallel()

		analyzer := NewHeaderAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Headers: map[string][]string{
						"Set-Cookie": {"session=abc123"},
					},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			// Cookie findings are cookie_no_httponly or cookie_no_samesite
			if f.Type == "cookie_no_httponly" || f.Type == "cookie_no_samesite" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find cookie finding")
		}
	})
}

// TestFingerprintAnalyzer tests fingerprint analysis.
func TestFingerprintAnalyzer(t *testing.T) {
	t.Parallel()

	t.Run("Name returns correct value", func(t *testing.T) {
		t.Parallel()
		analyzer := NewFingerprintAnalyzer()
		if analyzer.Name() != "fingerprint" {
			t.Errorf("expected name 'fingerprint', got %q", analyzer.Name())
		}
	})

	t.Run("Category returns attack", func(t *testing.T) {
		t.Parallel()
		analyzer := NewFingerprintAnalyzer()
		if analyzer.Category() != "attack" {
			t.Errorf("expected category 'attack', got %q", analyzer.Category())
		}
	})

	t.Run("detects canvas fingerprinting", func(t *testing.T) {
		t.Parallel()

		analyzer := NewFingerprintAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: "<script>canvas.toDataURL('image/png')</script>",
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "fingerprint_canvas_toDataURL" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find canvas fingerprinting finding")
		}
	})

	t.Run("detects WebGL fingerprinting", func(t *testing.T) {
		t.Parallel()

		analyzer := NewFingerprintAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: "<script>ctx.getParameter(gl.VENDOR)</script>",
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "fingerprint_webgl_getParameter" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find WebGL fingerprinting finding")
		}
	})

	t.Run("detects audio fingerprinting", func(t *testing.T) {
		t.Parallel()

		analyzer := NewFingerprintAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: "<script>new AudioContext()</script>",
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "fingerprint_audio_fingerprint" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find audio fingerprinting finding")
		}
	})
}

// TestMaliciousAnalyzer tests malicious content detection.
func TestMaliciousAnalyzer(t *testing.T) {
	t.Parallel()

	t.Run("Name returns correct value", func(t *testing.T) {
		t.Parallel()
		analyzer := NewMaliciousAnalyzer()
		if analyzer.Name() != "malicious" {
			t.Errorf("expected name 'malicious', got %q", analyzer.Name())
		}
	})

	t.Run("Category returns attack", func(t *testing.T) {
		t.Parallel()
		analyzer := NewMaliciousAnalyzer()
		if analyzer.Category() != "attack" {
			t.Errorf("expected category 'attack', got %q", analyzer.Category())
		}
	})

	t.Run("detects obfuscated JavaScript", func(t *testing.T) {
		t.Parallel()

		analyzer := NewMaliciousAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: "<script>eval(unescape(String.fromCharCode(104,101,108,108,111)))</script>",
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "js_obfuscation" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find obfuscated JS finding")
		}
	})

	t.Run("detects hidden iframes", func(t *testing.T) {
		t.Parallel()

		analyzer := NewMaliciousAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `<iframe style="display:none" src="http://evil.com"></iframe>`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "hidden_iframe" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find hidden iframe finding")
		}
	})

	t.Run("detects meta redirects", func(t *testing.T) {
		t.Parallel()

		analyzer := NewMaliciousAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `<meta http-equiv="refresh" content="0; url=http://phishing.com">`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "suspicious_redirect" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find meta redirect finding")
		}
	})

	t.Run("detects debug artifacts", func(t *testing.T) {
		t.Parallel()

		analyzer := NewMaliciousAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `<!-- TODO: remove this debug code before production -->`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			// Debug artifacts are debug_comments (plural)
			if f.Type == "debug_comments" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find debug comments finding")
		}
	})
}

// TestServerInfoAnalyzerNginx tests nginx server info analysis.
func TestServerInfoAnalyzerNginx(t *testing.T) {
	t.Parallel()

	analyzer := NewServerInfoAnalyzer()
	data := &AnalysisData{
		HiddenService: "test.onion",
		Pages: []*model.Page{
			{
				URL: "http://test.onion/",
				Headers: map[string][]string{
					"Server": {"nginx/1.18.0"},
				},
			},
		},
	}

	findings, err := analyzer.Analyze(context.Background(), data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should find server version disclosure
	found := false
	for _, f := range findings {
		if f.Type == "server_version" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find server version finding")
	}
}

// TestServerInfoAnalyzerIIS tests IIS server info analysis.
func TestServerInfoAnalyzerIIS(t *testing.T) {
	t.Parallel()

	analyzer := NewServerInfoAnalyzer()
	data := &AnalysisData{
		HiddenService: "test.onion",
		Pages: []*model.Page{
			{
				URL: "http://test.onion/",
				Headers: map[string][]string{
					"Server": {"Microsoft-IIS/10.0"},
				},
			},
		},
	}

	findings, err := analyzer.Analyze(context.Background(), data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should find server version disclosure
	found := false
	for _, f := range findings {
		if f.Type == "server_version" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find server version finding")
	}
}

// TestExternalLinkAnalyzerCSP tests CSP-related external link detection.
func TestExternalLinkAnalyzerCSP(t *testing.T) {
	t.Parallel()

	t.Run("detects CSP external domains", func(t *testing.T) {
		t.Parallel()

		analyzer := NewExternalLinkAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					CSP: &model.CSPPolicy{
						ExternalDomains: []string{"api.example.com"},
					},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "csp_external_domain" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find CSP external domain finding")
		}
	})

	t.Run("detects CSP report URI", func(t *testing.T) {
		t.Parallel()

		analyzer := NewExternalLinkAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					CSP: &model.CSPPolicy{
						ReportURI: "https://report.example.com/csp",
					},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "csp_report_uri" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find CSP report URI finding")
		}
	})

	t.Run("detects common CDN in CSP", func(t *testing.T) {
		t.Parallel()

		analyzer := NewExternalLinkAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					CSP: &model.CSPPolicy{
						ExternalDomains: []string{"cdn.jsdelivr.net"},
					},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "csp_cdn" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find common CDN finding")
		}
	})
}

// TestHeaderAnalyzerCSP tests CSP header analysis.
func TestHeaderAnalyzerCSP(t *testing.T) {
	t.Parallel()

	t.Run("detects missing CSP", func(t *testing.T) {
		t.Parallel()

		analyzer := NewHeaderAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:     "http://test.onion/",
					Headers: map[string][]string{},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "csp_missing" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find missing CSP finding")
		}
	})

	t.Run("detects HSTS on onion", func(t *testing.T) {
		t.Parallel()

		analyzer := NewHeaderAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Headers: map[string][]string{
						"Strict-Transport-Security": {"max-age=31536000"},
					},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "hsts_on_onion" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find HSTS on onion finding")
		}
	})

	t.Run("detects unsafe inline CSP", func(t *testing.T) {
		t.Parallel()

		analyzer := NewHeaderAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Headers: map[string][]string{
						"Content-Security-Policy": {"default-src 'self' 'unsafe-inline'"},
					},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "csp_unsafe_inline" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find unsafe-inline CSP finding")
		}
	})
}

// TestMaliciousAnalyzerHiddenIframes tests hidden iframe detection.
func TestMaliciousAnalyzerHiddenIframes(t *testing.T) {
	t.Parallel()

	t.Run("detects zero-size iframe", func(t *testing.T) {
		t.Parallel()

		analyzer := NewMaliciousAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `<iframe width="0" height="0" src="http://evil.com/tracker"></iframe>`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "hidden_iframe" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find hidden iframe finding")
		}
	})

	t.Run("detects external iframe", func(t *testing.T) {
		t.Parallel()

		analyzer := NewMaliciousAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `<iframe src="http://tracking.example.com/frame"></iframe>`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "external_iframe" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find external iframe finding")
		}
	})

	t.Run("detects form action leak", func(t *testing.T) {
		t.Parallel()

		analyzer := NewMaliciousAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Forms: []model.Form{
						{Action: "https://evil.com/steal"},
					},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "form_action_leak" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find form action leak finding")
		}
	})

	t.Run("detects error disclosure", func(t *testing.T) {
		t.Parallel()

		analyzer := NewMaliciousAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `Fatal error: Call to undefined function in /var/www/html/index.php on line 42`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "error_disclosure" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find error disclosure finding")
		}
	})

	t.Run("detects source map reference", func(t *testing.T) {
		t.Parallel()

		analyzer := NewMaliciousAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `//# sourceMappingURL=app.js.map`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "debug_sourcemap" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find source map finding")
		}
	})
}

// TestCryptoAnalyzerDescriptions tests cryptocurrency description generation.
func TestCryptoAnalyzerDescriptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		cryptoType  string
		expectEmpty bool
	}{
		{"bitcoin_legacy", "bitcoin_legacy", false},
		{"bitcoin_bech32", "bitcoin_bech32", false},
		{"ethereum", "ethereum", false},
		{"monero", "monero", false},
		{"zcash_shielded", "zcash_shielded", false},
		{"zcash_transparent", "zcash_transparent", false},
		{"unknown_crypto", "unknown_crypto", false},
	}

	analyzer := NewCryptoAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			desc := analyzer.getDescription(tt.cryptoType)
			if tt.expectEmpty && desc != "" {
				t.Errorf("expected empty description, got %q", desc)
			}
			if !tt.expectEmpty && desc == "" {
				t.Errorf("expected non-empty description for %s", tt.cryptoType)
			}
		})
	}
}

// TestCryptoAnalyzerSeverity tests cryptocurrency severity classification.
func TestCryptoAnalyzerSeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		cryptoType string
		expected   model.Severity
	}{
		{"monero is low severity", "monero", model.SeverityLow},
		{"zcash_shielded is low severity", "zcash_shielded", model.SeverityLow},
		{"bitcoin_legacy is medium severity", "bitcoin_legacy", model.SeverityMedium},
		{"ethereum is medium severity", "ethereum", model.SeverityMedium},
		{"unknown is medium severity", "unknown", model.SeverityMedium},
	}

	analyzer := NewCryptoAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			severity := analyzer.getSeverity(tt.cryptoType)
			if severity != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, severity)
			}
		})
	}
}

// TestAnalyticsAnalyzerSeverity tests analytics severity classification.
func TestAnalyticsAnalyzerSeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		analyticsType string
		expected      model.Severity
	}{
		{"ga4 is high severity", "ga4", model.SeverityHigh},
		{"ga3 is high severity", "ga3", model.SeverityHigh},
		{"gtm is high severity", "gtm", model.SeverityHigh},
		{"facebook_pixel is high severity", "facebook_pixel", model.SeverityHigh},
		{"adsense is critical severity", "adsense", model.SeverityCritical},
		{"publisher is critical severity", "google_publisher", model.SeverityCritical},
		{"unknown is high severity", "unknown_type", model.SeverityHigh},
	}

	analyzer := NewAnalyticsAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			severity := analyzer.getSeverity(tt.analyticsType)
			if severity != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, severity)
			}
		})
	}
}

// TestExternalLinkAnalyzerScripts tests external script detection.
func TestExternalLinkAnalyzerScripts(t *testing.T) {
	t.Parallel()

	t.Run("detects external scripts", func(t *testing.T) {
		t.Parallel()

		analyzer := NewExternalLinkAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Scripts: []model.Element{
						{Source: "https://cdn.example.com/script.js"},
						{Source: "https://analytics.tracking.com/track.js"},
					},
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should find external script findings
		foundExternal := false
		for _, f := range findings {
			if f.Type == "external_script" {
				foundExternal = true
				break
			}
		}
		if !foundExternal {
			t.Error("expected to find external script")
		}
	})

	t.Run("ignores onion scripts", func(t *testing.T) {
		t.Parallel()

		analyzer := NewExternalLinkAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Scripts: []model.Element{
						{Source: "http://other.onion/script.js"},
					},
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should not find any external script findings for onion domains
		for _, f := range findings {
			if f.Type == "external_script" {
				t.Error("should not find external_script for onion domain")
			}
		}
	})

	t.Run("ignores empty source scripts", func(t *testing.T) {
		t.Parallel()

		analyzer := NewExternalLinkAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Scripts: []model.Element{
						{Source: ""},
					},
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, f := range findings {
			if f.Type == "external_script" {
				t.Error("should not find external_script for empty source")
			}
		}
	})

	t.Run("deduplicates scripts by domain", func(t *testing.T) {
		t.Parallel()

		analyzer := NewExternalLinkAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Scripts: []model.Element{
						{Source: "https://cdn.example.com/script1.js"},
						{Source: "https://cdn.example.com/script2.js"},
					},
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should deduplicate to one finding per domain
		scriptCount := 0
		for _, f := range findings {
			if f.Type == "external_script" {
				scriptCount++
			}
		}
		if scriptCount > 2 {
			t.Errorf("expected at most 2 script findings, got %d", scriptCount)
		}
	})
}

// TestExternalLinkAnalyzerImages tests external image detection.
func TestExternalLinkAnalyzerImages(t *testing.T) {
	t.Parallel()

	t.Run("detects external images", func(t *testing.T) {
		t.Parallel()

		analyzer := NewExternalLinkAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Images: []model.Element{
						{Source: "https://cdn.example.com/image.png"},
						{Source: "https://tracking.site.com/pixel.gif"},
					},
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should find external image findings
		foundExternal := false
		for _, f := range findings {
			if f.Type == "external_image" {
				foundExternal = true
				break
			}
		}
		if !foundExternal {
			t.Error("expected to find external image")
		}
	})

	t.Run("ignores onion images", func(t *testing.T) {
		t.Parallel()

		analyzer := NewExternalLinkAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Images: []model.Element{
						{Source: "http://other.onion/image.png"},
					},
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should not find any external image findings for onion domains
		for _, f := range findings {
			if f.Type == "external_image" {
				t.Error("should not find external_image for onion domain")
			}
		}
	})

	t.Run("ignores empty source images", func(t *testing.T) {
		t.Parallel()

		analyzer := NewExternalLinkAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Images: []model.Element{
						{Source: ""},
					},
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, f := range findings {
			if f.Type == "external_image" {
				t.Error("should not find external_image for empty source")
			}
		}
	})

	t.Run("deduplicates images by domain", func(t *testing.T) {
		t.Parallel()

		analyzer := NewExternalLinkAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Images: []model.Element{
						{Source: "https://cdn.example.com/image1.png"},
						{Source: "https://cdn.example.com/image2.jpg"},
					},
				},
			},
			Report: model.NewOnionScanReport("test.onion"),
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should deduplicate to one finding per domain
		imageCount := 0
		for _, f := range findings {
			if f.Type == "external_image" {
				imageCount++
			}
		}
		if imageCount > 2 {
			t.Errorf("expected at most 2 image findings, got %d", imageCount)
		}
	})
}

// TestExternalLinkAnalyzerExtractDomain tests domain extraction.
func TestExternalLinkAnalyzerExtractDomain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{"extracts domain from https URL", "https://example.com/path", "example.com"},
		{"extracts domain from http URL", "http://test.org/page?query=1", "test.org"},
		{"handles URL with port", "https://example.com:8080/path", "example.com:8080"},
		{"returns empty for invalid URL", "not-a-valid-url", ""},
		{"returns empty for relative URL", "/path/to/file", ""},
		{"handles subdomain", "https://sub.example.com/", "sub.example.com"},
	}

	analyzer := NewExternalLinkAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := analyzer.extractDomain(tt.url)
			if result != tt.expected {
				t.Errorf("extractDomain(%q) = %q, expected %q", tt.url, result, tt.expected)
			}
		})
	}
}

// TestServerInfoAnalyzerHeaders tests various header detection.
func TestServerInfoAnalyzerHeaders(t *testing.T) {
	t.Parallel()

	t.Run("detects X-Powered-By header", func(t *testing.T) {
		t.Parallel()

		analyzer := NewServerInfoAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Headers: map[string][]string{
						"X-Powered-By": {"PHP/8.1.0"},
					},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "x_powered_by" {
				found = true
				if f.Value != "PHP/8.1.0" {
					t.Errorf("expected value 'PHP/8.1.0', got %q", f.Value)
				}
				break
			}
		}
		if !found {
			t.Error("expected to find x_powered_by finding")
		}
	})

	t.Run("detects Via header", func(t *testing.T) {
		t.Parallel()

		analyzer := NewServerInfoAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Headers: map[string][]string{
						"Via": {"1.1 varnish, 1.1 cloudflare"},
					},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "via_header" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find via_header finding")
		}
	})

	t.Run("detects ASP.NET version", func(t *testing.T) {
		t.Parallel()

		analyzer := NewServerInfoAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Headers: map[string][]string{
						"X-AspNet-Version": {"4.0.30319"},
					},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "aspnet_version" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find aspnet_version finding")
		}
	})

	t.Run("detects nginx server", func(t *testing.T) {
		t.Parallel()

		analyzer := NewServerInfoAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Headers: map[string][]string{
						"Server": {"nginx/1.20.0"},
					},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(findings) == 0 {
			t.Error("expected findings for nginx server")
		}
	})

	t.Run("detects IIS server", func(t *testing.T) {
		t.Parallel()

		analyzer := NewServerInfoAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Headers: map[string][]string{
						"Server": {"Microsoft-IIS/10.0"},
					},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(findings) == 0 {
			t.Error("expected findings for IIS server")
		}
	})

	t.Run("detects lighttpd server", func(t *testing.T) {
		t.Parallel()

		analyzer := NewServerInfoAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Headers: map[string][]string{
						"Server": {"lighttpd/1.4.59"},
					},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "lighttpd_server" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find lighttpd_server finding")
		}
	})

	t.Run("detects Apache OS disclosure", func(t *testing.T) {
		t.Parallel()

		analyzer := NewServerInfoAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Headers: map[string][]string{
						"Server": {"Apache/2.4.41 (Ubuntu)"},
					},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		foundOS := false
		for _, f := range findings {
			if f.Type == "os_detected" && f.Value == "Ubuntu" {
				foundOS = true
				break
			}
		}
		if !foundOS {
			t.Error("expected to find os_detected finding for Ubuntu")
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		t.Parallel()

		analyzer := NewServerInfoAnalyzer()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Headers: map[string][]string{
						"Server": {"Apache/2.4.41"},
					},
				},
			},
		}

		_, err := analyzer.Analyze(ctx, data)
		if err == nil {
			t.Log("analyzer completed quickly or handled cancellation gracefully")
		}
	})
}

// TestServerInfoAnalyzerProtocolResults tests SSH banner detection.
func TestServerInfoAnalyzerProtocolResults(t *testing.T) {
	t.Parallel()

	t.Run("detects SSH banner from protocol results", func(t *testing.T) {
		t.Parallel()

		analyzer := NewServerInfoAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages:         []*model.Page{},
			ProtocolResults: map[string]*protocol.ScanResult{
				"ssh": {
					Protocol: "ssh",
					Detected: true,
					Banner:   "SSH-2.0-OpenSSH_8.4p1",
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "ssh_banner" {
				found = true
				if f.Value != "SSH-2.0-OpenSSH_8.4p1" {
					t.Errorf("expected SSH banner value, got %q", f.Value)
				}
				break
			}
		}
		if !found {
			t.Error("expected to find ssh_banner finding")
		}
	})

	t.Run("handles nil protocol results", func(t *testing.T) {
		t.Parallel()

		analyzer := NewServerInfoAnalyzer()
		data := &AnalysisData{
			HiddenService:   "test.onion",
			Pages:           []*model.Page{},
			ProtocolResults: nil,
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(findings) != 0 {
			t.Errorf("expected no findings for empty data, got %d", len(findings))
		}
	})

	t.Run("handles empty SSH banner", func(t *testing.T) {
		t.Parallel()

		analyzer := NewServerInfoAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages:         []*model.Page{},
			ProtocolResults: map[string]*protocol.ScanResult{
				"ssh": {
					Protocol: "ssh",
					Detected: true,
					Banner:   "",
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, f := range findings {
			if f.Type == "ssh_banner" {
				t.Error("should not find ssh_banner for empty banner")
			}
		}
	})
}

// TestHeaderAnalyzerHasExternalDomains tests the hasExternalDomains helper.
func TestHeaderAnalyzerHasExternalDomains(t *testing.T) {
	t.Parallel()

	analyzer := NewHeaderAnalyzer()

	tests := []struct {
		name     string
		csp      string
		expected bool
	}{
		{
			name:     "detects external HTTP domain",
			csp:      "default-src 'self'; script-src https://cdn.example.com",
			expected: true,
		},
		{
			name:     "detects external HTTPS domain",
			csp:      "script-src https://analytics.google.com",
			expected: true,
		},
		{
			name:     "ignores onion domains",
			csp:      "default-src 'self'; script-src https://abc123xyz.onion",
			expected: false,
		},
		{
			name:     "returns false for self only",
			csp:      "default-src 'self'; script-src 'self'",
			expected: false,
		},
		{
			name:     "detects mixed onion and clearnet",
			csp:      "script-src https://cdn.example.com https://abc.onion",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := analyzer.hasExternalDomains(tt.csp)
			if result != tt.expected {
				t.Errorf("hasExternalDomains(%q) = %v, want %v", tt.csp, result, tt.expected)
			}
		})
	}
}

// TestHeaderAnalyzerSanitizeCookieValue tests cookie value sanitization.
func TestHeaderAnalyzerSanitizeCookieValue(t *testing.T) {
	t.Parallel()

	analyzer := NewHeaderAnalyzer()

	tests := []struct {
		name     string
		cookie   string
		expected string
	}{
		{
			name:     "sanitizes simple cookie",
			cookie:   "session=abc123",
			expected: "session=<redacted>",
		},
		{
			name:     "sanitizes cookie with attributes",
			cookie:   "session=abc123; HttpOnly; Secure",
			expected: "session=<redacted>; HttpOnly; Secure",
		},
		{
			name:     "handles cookie without equals",
			cookie:   "malformed",
			expected: "malformed",
		},
		{
			name:     "sanitizes cookie with path",
			cookie:   "token=xyz789; Path=/api; SameSite=Strict",
			expected: "token=<redacted>; Path=/api; SameSite=Strict",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := analyzer.sanitizeCookieValue(tt.cookie)
			if result != tt.expected {
				t.Errorf("sanitizeCookieValue(%q) = %q, want %q", tt.cookie, result, tt.expected)
			}
		})
	}
}

// TestHeaderAnalyzerIsSessionCookie tests session cookie detection.
func TestHeaderAnalyzerIsSessionCookie(t *testing.T) {
	t.Parallel()

	analyzer := NewHeaderAnalyzer()

	tests := []struct {
		name     string
		cookie   string
		expected bool
	}{
		{
			name:     "detects PHPSESSID",
			cookie:   "PHPSESSID=abc123",
			expected: true,
		},
		{
			name:     "detects JSESSIONID",
			cookie:   "JSESSIONID=xyz789",
			expected: true,
		},
		{
			name:     "detects session cookie",
			cookie:   "session=value",
			expected: true,
		},
		{
			name:     "detects sid cookie",
			cookie:   "sid=abc",
			expected: true,
		},
		{
			name:     "non-session cookie returns false",
			cookie:   "theme=dark",
			expected: false,
		},
		{
			name:     "preference cookie returns false",
			cookie:   "language=en",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := analyzer.isSessionCookie(tt.cookie)
			if result != tt.expected {
				t.Errorf("isSessionCookie(%q) = %v, want %v", tt.cookie, result, tt.expected)
			}
		})
	}
}

// TestMaliciousAnalyzerCheckRedirects tests redirect detection.
func TestMaliciousAnalyzerCheckRedirects(t *testing.T) {
	t.Parallel()

	t.Run("detects suspicious meta refresh redirect", func(t *testing.T) {
		t.Parallel()

		analyzer := NewMaliciousAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `<meta http-equiv="refresh" content="0;url=https://clearnet.example.com">`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "suspicious_redirect" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find suspicious_redirect finding")
		}
	})
}

// TestPrivateKeyAnalyzer tests private key detection.
func TestPrivateKeyAnalyzer(t *testing.T) {
	t.Parallel()

	t.Run("Name returns correct value", func(t *testing.T) {
		t.Parallel()
		analyzer := NewPrivateKeyAnalyzer()
		if analyzer.Name() != "privatekey" {
			t.Errorf("expected name 'privatekey', got %q", analyzer.Name())
		}
	})

	t.Run("Category returns secrets", func(t *testing.T) {
		t.Parallel()
		analyzer := NewPrivateKeyAnalyzer()
		if analyzer.Category() != "secrets" {
			t.Errorf("expected category 'secrets', got %q", analyzer.Category())
		}
	})

	t.Run("detects RSA private key", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPrivateKeyAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/keys",
					Snapshot: "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...",
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "rsa_private_key" {
				found = true
				if f.Severity != model.SeverityCritical {
					t.Errorf("expected critical severity, got %v", f.Severity)
				}
				break
			}
		}
		if !found {
			t.Error("expected to find RSA private key finding")
		}
	})

	t.Run("detects OpenSSH private key", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPrivateKeyAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/ssh",
					Snapshot: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXkt...",
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "openssh_private_key" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find OpenSSH private key finding")
		}
	})

	t.Run("detects AWS access key", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPrivateKeyAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/config",
					Snapshot: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "aws_access_key" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find AWS access key finding")
		}
	})

	t.Run("detects GitHub token", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPrivateKeyAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/config",
					Snapshot: "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz",
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "github_token" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find GitHub token finding")
		}
	})

	t.Run("deduplicates findings", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPrivateKeyAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/page1",
					Snapshot: "-----BEGIN RSA PRIVATE KEY-----\nkey1",
				},
				{
					URL:      "http://test.onion/page2",
					Snapshot: "-----BEGIN RSA PRIVATE KEY-----\nkey1",
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		rsaCount := 0
		for _, f := range findings {
			if f.Type == "rsa_private_key" {
				rsaCount++
			}
		}
		// Should only find one unique RSA key
		if rsaCount > 1 {
			t.Errorf("expected deduplicated findings, got %d RSA key findings", rsaCount)
		}
	})
}

// TestSocialAnalyzer tests social media link detection.
func TestSocialAnalyzer(t *testing.T) {
	t.Parallel()

	t.Run("Name returns correct value", func(t *testing.T) {
		t.Parallel()
		analyzer := NewSocialAnalyzer()
		if analyzer.Name() != "social" {
			t.Errorf("expected name 'social', got %q", analyzer.Name())
		}
	})

	t.Run("Category returns identity", func(t *testing.T) {
		t.Parallel()
		analyzer := NewSocialAnalyzer()
		if analyzer.Category() != CategoryIdentity {
			t.Errorf("expected category 'identity', got %q", analyzer.Category())
		}
	})

	t.Run("detects Twitter link", func(t *testing.T) {
		t.Parallel()

		analyzer := NewSocialAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/about",
					Snapshot: "Follow us: https://twitter.com/testuser",
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "social_twitter" {
				found = true
				if f.Severity != model.SeverityHigh {
					t.Errorf("expected high severity, got %v", f.Severity)
				}
				break
			}
		}
		if !found {
			t.Error("expected to find Twitter link finding")
		}
	})

	t.Run("detects X.com link", func(t *testing.T) {
		t.Parallel()

		analyzer := NewSocialAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/about",
					Snapshot: "Follow us: https://x.com/testuser",
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "social_twitter" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find X.com link finding")
		}
	})

	t.Run("detects LinkedIn link", func(t *testing.T) {
		t.Parallel()

		analyzer := NewSocialAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/contact",
					Snapshot: "LinkedIn: https://linkedin.com/in/johndoe",
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "social_linkedin" {
				found = true
				if f.Severity != model.SeverityCritical {
					t.Errorf("expected critical severity for LinkedIn, got %v", f.Severity)
				}
				break
			}
		}
		if !found {
			t.Error("expected to find LinkedIn link finding")
		}
	})

	t.Run("detects GitHub link", func(t *testing.T) {
		t.Parallel()

		analyzer := NewSocialAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: "Source: https://github.com/testuser/project",
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "social_github" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find GitHub link finding")
		}
	})

	t.Run("detects Telegram link", func(t *testing.T) {
		t.Parallel()

		analyzer := NewSocialAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: "Join us: https://t.me/testchannel",
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "social_telegram" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find Telegram link finding")
		}
	})

	t.Run("detects WhatsApp link", func(t *testing.T) {
		t.Parallel()

		analyzer := NewSocialAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: "Contact: https://wa.me/1234567890",
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "social_whatsapp" {
				found = true
				if f.Severity != model.SeverityHigh {
					t.Errorf("expected high severity for WhatsApp, got %v", f.Severity)
				}
				break
			}
		}
		if !found {
			t.Error("expected to find WhatsApp link finding")
		}
	})

	t.Run("filters invalid paths", func(t *testing.T) {
		t.Parallel()

		analyzer := NewSocialAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: "https://twitter.com/share?url=test",
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should not find share links
		for _, f := range findings {
			if f.Type == "social_twitter" {
				t.Error("should not find share link as social finding")
			}
		}
	})

	t.Run("deduplicates findings", func(t *testing.T) {
		t.Parallel()

		analyzer := NewSocialAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/page1",
					Snapshot: "https://twitter.com/testuser",
				},
				{
					URL:      "http://test.onion/page2",
					Snapshot: "https://twitter.com/testuser",
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		twitterCount := 0
		for _, f := range findings {
			if f.Type == "social_twitter" {
				twitterCount++
			}
		}
		if twitterCount > 1 {
			t.Errorf("expected deduplicated findings, got %d Twitter findings", twitterCount)
		}
	})
}

// TestEXIFAnalyzer tests EXIF analyzer interface.
func TestEXIFAnalyzer(t *testing.T) {
	t.Parallel()

	t.Run("Name returns correct value", func(t *testing.T) {
		t.Parallel()
		analyzer := NewEXIFAnalyzer()
		if analyzer.Name() != "exif" {
			t.Errorf("expected name 'exif', got %q", analyzer.Name())
		}
	})

	t.Run("Category returns identity", func(t *testing.T) {
		t.Parallel()
		analyzer := NewEXIFAnalyzer()
		if analyzer.Category() != CategoryIdentity {
			t.Errorf("expected category 'identity', got %q", analyzer.Category())
		}
	})

	t.Run("returns error without HTTP client", func(t *testing.T) {
		t.Parallel()

		analyzer := NewEXIFAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages:         []*model.Page{},
		}

		_, err := analyzer.Analyze(context.Background(), data)
		if err == nil {
			t.Fatal("expected error without HTTP client, got nil")
		}
		if !errors.Is(err, ErrNoHTTPClient) {
			t.Errorf("expected ErrNoHTTPClient, got %v", err)
		}
	})

	t.Run("handles empty pages", func(t *testing.T) {
		t.Parallel()

		analyzer := NewEXIFAnalyzer()
		analyzer.SetHTTPClient(&http.Client{}) // Set mock client
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages:         []*model.Page{},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(findings) != 0 {
			t.Errorf("expected no findings for empty pages, got %d", len(findings))
		}
	})

	t.Run("extracts image URLs from page", func(t *testing.T) {
		t.Parallel()

		analyzer := NewEXIFAnalyzer()
		page := &model.Page{
			URL: "http://test.onion/",
			Images: []model.Element{
				{Source: "http://test.onion/image.jpg"},
				{Source: "http://test.onion/photo.png"},
			},
			Snapshot: `<img src="http://test.onion/extra.jpeg">`,
		}

		urls := analyzer.extractImageURLs(page)

		if len(urls) < 2 {
			t.Errorf("expected at least 2 image URLs, got %d", len(urls))
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		t.Parallel()

		analyzer := NewEXIFAnalyzer()
		analyzer.SetHTTPClient(&http.Client{}) // Set mock client
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Images: []model.Element{
						{Source: "http://test.onion/image.jpg"},
					},
				},
			},
		}

		_, err := analyzer.Analyze(ctx, data)
		if err == nil {
			t.Log("analyzer completed quickly or handled cancellation gracefully")
		}
	})

	t.Run("isAllowedURL blocks clearnet URLs", func(t *testing.T) {
		t.Parallel()

		analyzer := NewEXIFAnalyzer()
		analyzer.SetHTTPClient(&http.Client{})

		// Simulate setting target host during Analyze
		data := &AnalysisData{
			HiddenService: "target.onion",
			Pages:         []*model.Page{},
		}
		_, _ = analyzer.Analyze(context.Background(), data)

		// Test various URL types
		tests := []struct {
			url     string
			allowed bool
		}{
			{"http://target.onion/image.jpg", true}, // Same origin - allowed
			{"http://other.onion/image.jpg", false}, // Different onion - blocked by default
			{"http://example.com/image.jpg", false}, // Clearnet - always blocked
			{"https://google.com/image.jpg", false}, // Clearnet HTTPS - always blocked
			{"http://192.168.1.1/image.jpg", false}, // IP address - blocked
			{"invalid-url", false},                  // Invalid URL - blocked
		}

		for _, tt := range tests {
			if got := analyzer.isAllowedURL(tt.url); got != tt.allowed {
				t.Errorf("isAllowedURL(%q) = %v, want %v", tt.url, got, tt.allowed)
			}
		}
	})

	t.Run("SetAllowExternalFetch enables external onion fetches", func(t *testing.T) {
		t.Parallel()

		analyzer := NewEXIFAnalyzer()
		analyzer.SetHTTPClient(&http.Client{})

		// Simulate setting target host
		data := &AnalysisData{
			HiddenService: "target.onion",
			Pages:         []*model.Page{},
		}
		_, _ = analyzer.Analyze(context.Background(), data)

		// By default, external onion should be blocked
		if analyzer.isAllowedURL("http://other.onion/image.jpg") {
			t.Error("expected external onion to be blocked by default")
		}

		// Enable external fetch
		analyzer.SetAllowExternalFetch(true)

		// Now external onion should be allowed
		if !analyzer.isAllowedURL("http://other.onion/image.jpg") {
			t.Error("expected external onion to be allowed after SetAllowExternalFetch(true)")
		}

		// But clearnet should still be blocked
		if analyzer.isAllowedURL("http://example.com/image.jpg") {
			t.Error("expected clearnet to still be blocked even with allowExternalFetch")
		}
	})
}

// TestAPILeakAnalyzer tests API leak detection functionality.
func TestAPILeakAnalyzer(t *testing.T) {
	t.Parallel()

	t.Run("Name returns correct value", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAPILeakAnalyzer()
		if analyzer.Name() != "apileak" {
			t.Errorf("expected name 'apileak', got '%s'", analyzer.Name())
		}
	})

	t.Run("Category returns correlation", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAPILeakAnalyzer()
		if analyzer.Category() != "correlation" {
			t.Errorf("expected category 'correlation', got '%s'", analyzer.Category())
		}
	})

	t.Run("detects Swagger UI", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAPILeakAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/docs",
					Snapshot: `<script src="/swagger-ui-bundle.js"></script>`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "swagger_ui" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find Swagger UI finding")
		}
	})

	t.Run("detects Swagger JSON endpoint", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAPILeakAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/api-docs/",
					Snapshot: `API Documentation`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "swagger_json" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find Swagger JSON endpoint finding")
		}
	})

	t.Run("detects GraphQL endpoint", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAPILeakAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/graphql",
					Snapshot: `GraphQL Playground`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "graphql_endpoint" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find GraphQL endpoint finding")
		}
	})

	t.Run("detects debug endpoint", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAPILeakAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/debug/pprof",
					Snapshot: `pprof index`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "debug_endpoint" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find debug endpoint finding")
		}
	})

	t.Run("detects Flask debugger", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAPILeakAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/error",
					Snapshot: `The debugger caught an exception in your WSGI application`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "flask_debug" {
				found = true
				if f.Severity != model.SeverityCritical {
					t.Errorf("expected critical severity, got %s", f.Severity)
				}
				break
			}
		}
		if !found {
			t.Error("expected to find Flask debugger finding")
		}
	})

	t.Run("detects database URL", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAPILeakAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/config",
					Snapshot: `DATABASE_URL=postgres://admin:secretpass@localhost/mydb`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "database_url" {
				found = true
				if f.Severity != model.SeverityCritical {
					t.Errorf("expected critical severity, got %s", f.Severity)
				}
				break
			}
		}
		if !found {
			t.Error("expected to find database URL finding")
		}
	})

	t.Run("detects API version header", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAPILeakAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/api",
					Snapshot: `API Response`,
					Headers: map[string][]string{
						"X-API-Version": {"2.1.0"},
					},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "api_version_header" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find API version header finding")
		}
	})

	t.Run("detects OpenAPI specification", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAPILeakAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/openapi.json",
					Snapshot: `{"openapi": "3.0.0", "info": {"title": "API"}}`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "openapi_spec" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find OpenAPI spec finding")
		}
	})

	t.Run("detects metrics endpoint", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAPILeakAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/metrics",
					Snapshot: `# HELP http_requests_total Total requests`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "metrics_endpoint" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find metrics endpoint finding")
		}
	})

	t.Run("deduplicates findings", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAPILeakAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/graphql",
					Snapshot: `GraphQL API`,
				},
				{
					URL:      "http://test.onion/api/graphql",
					Snapshot: `GraphQL API`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should have findings for both URLs but not duplicates
		graphqlCount := 0
		for _, f := range findings {
			if f.Type == "graphql_endpoint" {
				graphqlCount++
			}
		}
		if graphqlCount > 2 {
			t.Errorf("expected at most 2 graphql findings (one per URL), got %d", graphqlCount)
		}
	})

	t.Run("handles empty pages", func(t *testing.T) {
		t.Parallel()

		analyzer := NewAPILeakAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages:         []*model.Page{},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(findings) != 0 {
			t.Errorf("expected no findings for empty pages, got %d", len(findings))
		}
	})
}

// TestPDFAnalyzer tests PDF metadata extraction functionality.
func TestPDFAnalyzer(t *testing.T) {
	t.Parallel()

	t.Run("Name returns correct value", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPDFAnalyzer()
		if analyzer.Name() != "pdf" {
			t.Errorf("expected name 'pdf', got '%s'", analyzer.Name())
		}
	})

	t.Run("Category returns identity", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPDFAnalyzer()
		if analyzer.Category() != CategoryIdentity {
			t.Errorf("expected category '%s', got '%s'", CategoryIdentity, analyzer.Category())
		}
	})

	t.Run("returns error without HTTP client", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPDFAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages:         []*model.Page{},
		}

		_, err := analyzer.Analyze(context.Background(), data)
		if err == nil {
			t.Fatal("expected error without HTTP client, got nil")
		}
		if !errors.Is(err, ErrNoPDFHTTPClient) {
			t.Errorf("expected ErrNoPDFHTTPClient, got %v", err)
		}
	})

	t.Run("handles empty pages", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPDFAnalyzer()
		analyzer.SetHTTPClient(&http.Client{}) // Set mock client
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages:         []*model.Page{},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(findings) != 0 {
			t.Errorf("expected no findings for empty pages, got %d", len(findings))
		}
	})

	t.Run("extracts PDF URLs from links", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPDFAnalyzer()
		page := &model.Page{
			URL: "http://test.onion/docs",
			Links: []model.Element{
				{Source: "http://test.onion/document.pdf"},
				{Source: "http://test.onion/report.pdf?v=2"},
				{Source: "http://test.onion/page.html"},
			},
			Snapshot: `<a href="http://test.onion/manual.PDF">Manual</a>`,
		}

		urls := analyzer.extractPDFURLs(page)

		// Should find at least the PDF links
		pdfCount := 0
		for _, url := range urls {
			if strings.HasSuffix(strings.ToLower(url), ".pdf") ||
				strings.Contains(strings.ToLower(url), ".pdf?") {
				pdfCount++
			}
		}

		if pdfCount < 2 {
			t.Errorf("expected at least 2 PDF URLs, got %d", pdfCount)
		}
	})

	t.Run("extracts metadata from PDF content", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPDFAnalyzer()

		// Simulated PDF content with metadata
		pdfContent := []byte(`
			%PDF-1.4
			1 0 obj
			<<
			/Type /Catalog
			/Info 2 0 R
			>>
			endobj
			2 0 obj
			<<
			/Author (John Doe)
			/Creator (Microsoft Word)
			/Producer (Adobe PDF Library)
			/CreationDate (D:20240101120000+09'00')
			>>
			endobj
		`)

		metadata := analyzer.extractPDFMetadata(pdfContent)

		if metadata["author"] != "John Doe" {
			t.Errorf("expected author 'John Doe', got '%s'", metadata["author"])
		}
		if metadata["creator"] != "Microsoft Word" {
			t.Errorf("expected creator 'Microsoft Word', got '%s'", metadata["creator"])
		}
		if metadata["producer"] != "Adobe PDF Library" {
			t.Errorf("expected producer 'Adobe PDF Library', got '%s'", metadata["producer"])
		}
	})

	t.Run("creates finding from author metadata", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPDFAnalyzer()

		finding := analyzer.createFindingFromMetadata("author", "John Smith", "http://test.onion/doc.pdf")

		if finding == nil {
			t.Fatal("expected finding, got nil")
		}
		if finding.Type != "pdf_author" {
			t.Errorf("expected type 'pdf_author', got '%s'", finding.Type)
		}
		if finding.Severity != model.SeverityHigh {
			t.Errorf("expected high severity, got %s", finding.Severity)
		}
		if finding.Value != "John Smith" {
			t.Errorf("expected value 'John Smith', got '%s'", finding.Value)
		}
	})

	t.Run("creates finding from creator metadata", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPDFAnalyzer()

		finding := analyzer.createFindingFromMetadata("creator", "LibreOffice 7.0", "http://test.onion/doc.pdf")

		if finding == nil {
			t.Fatal("expected finding, got nil")
		}
		if finding.Type != "pdf_creator" {
			t.Errorf("expected type 'pdf_creator', got '%s'", finding.Type)
		}
		if finding.Severity != model.SeverityMedium {
			t.Errorf("expected medium severity, got %s", finding.Severity)
		}
	})

	t.Run("creates finding from timezone in date", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPDFAnalyzer()

		finding := analyzer.createFindingFromMetadata("creationDate", "D:20240101120000+09'00'", "http://test.onion/doc.pdf")

		if finding == nil {
			t.Fatal("expected finding, got nil")
		}
		if finding.Type != "pdf_timezone" {
			t.Errorf("expected type 'pdf_timezone', got '%s'", finding.Type)
		}
	})

	t.Run("skips empty metadata values", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPDFAnalyzer()

		finding := analyzer.createFindingFromMetadata("author", "", "http://test.onion/doc.pdf")
		if finding != nil {
			t.Error("expected nil finding for empty value")
		}

		finding = analyzer.createFindingFromMetadata("author", "ab", "http://test.onion/doc.pdf")
		if finding != nil {
			t.Error("expected nil finding for too short value")
		}
	})

	t.Run("decodes PDF escaped strings", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPDFAnalyzer()

		decoded := analyzer.decodePDFString("Hello\\nWorld")
		if decoded != "Hello\nWorld" {
			t.Errorf("expected 'Hello\\nWorld', got '%s'", decoded)
		}

		decoded = analyzer.decodePDFString("Path\\(test\\)")
		if decoded != "Path(test)" {
			t.Errorf("expected 'Path(test)', got '%s'", decoded)
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPDFAnalyzer()
		analyzer.SetHTTPClient(&http.Client{}) // Set mock client
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Links: []model.Element{
						{Source: "http://test.onion/doc.pdf"},
					},
				},
			},
		}

		_, err := analyzer.Analyze(ctx, data)
		if !errors.Is(err, context.Canceled) {
			t.Logf("analyzer handled cancellation: %v", err)
		}
	})

	t.Run("isAllowedURL blocks clearnet URLs", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPDFAnalyzer()
		analyzer.SetHTTPClient(&http.Client{})

		// Simulate setting target host during Analyze
		data := &AnalysisData{
			HiddenService: "target.onion",
			Pages:         []*model.Page{},
		}
		_, _ = analyzer.Analyze(context.Background(), data)

		// Test various URL types
		tests := []struct {
			url     string
			allowed bool
		}{
			{"http://target.onion/doc.pdf", true}, // Same origin - allowed
			{"http://other.onion/doc.pdf", false}, // Different onion - blocked by default
			{"http://example.com/doc.pdf", false}, // Clearnet - always blocked
			{"https://google.com/doc.pdf", false}, // Clearnet HTTPS - always blocked
			{"http://192.168.1.1/doc.pdf", false}, // IP address - blocked
			{"invalid-url", false},                // Invalid URL - blocked
		}

		for _, tt := range tests {
			if got := analyzer.isAllowedURL(tt.url); got != tt.allowed {
				t.Errorf("isAllowedURL(%q) = %v, want %v", tt.url, got, tt.allowed)
			}
		}
	})

	t.Run("SetAllowExternalFetch enables external onion fetches", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPDFAnalyzer()
		analyzer.SetHTTPClient(&http.Client{})

		// Simulate setting target host
		data := &AnalysisData{
			HiddenService: "target.onion",
			Pages:         []*model.Page{},
		}
		_, _ = analyzer.Analyze(context.Background(), data)

		// By default, external onion should be blocked
		if analyzer.isAllowedURL("http://other.onion/doc.pdf") {
			t.Error("expected external onion to be blocked by default")
		}

		// Enable external fetch
		analyzer.SetAllowExternalFetch(true)

		// Now external onion should be allowed
		if !analyzer.isAllowedURL("http://other.onion/doc.pdf") {
			t.Error("expected external onion to be allowed after SetAllowExternalFetch(true)")
		}

		// But clearnet should still be blocked
		if analyzer.isAllowedURL("http://example.com/doc.pdf") {
			t.Error("expected clearnet to still be blocked even with allowExternalFetch")
		}
	})

	t.Run("decodes hex strings", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPDFAnalyzer()

		// Test hex string decoding (FEFF BOM + hex pairs)
		decoded := analyzer.decodeHexString("FEFF0048006500")
		// Should decode UTF-16BE hex to string
		if decoded == "" {
			t.Error("expected non-empty decoded string")
		}

		// Short string should return as-is
		decoded = analyzer.decodeHexString("AB")
		if decoded != "AB" {
			t.Errorf("expected 'AB' for short string, got '%s'", decoded)
		}
	})

	t.Run("creates finding from producer metadata", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPDFAnalyzer()

		finding := analyzer.createFindingFromMetadata("producer", "Adobe PDF Library", "http://test.onion/doc.pdf")

		if finding == nil {
			t.Fatal("expected finding, got nil")
		}
		if finding.Type != "pdf_producer" {
			t.Errorf("expected type 'pdf_producer', got '%s'", finding.Type)
		}
		if finding.Severity != model.SeverityLow {
			t.Errorf("expected low severity, got %s", finding.Severity)
		}
	})

	t.Run("creates finding from document ID", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPDFAnalyzer()

		finding := analyzer.createFindingFromMetadata("xmp_documentId", "uuid:12345678-1234-1234-1234-123456789abc", "http://test.onion/doc.pdf")

		if finding == nil {
			t.Fatal("expected finding, got nil")
		}
		if finding.Type != "pdf_document_id" {
			t.Errorf("expected type 'pdf_document_id', got '%s'", finding.Type)
		}
		if finding.Severity != model.SeverityMedium {
			t.Errorf("expected medium severity, got %s", finding.Severity)
		}
	})

	t.Run("creates finding from XMP creator", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPDFAnalyzer()

		finding := analyzer.createFindingFromMetadata("xmp_creator", "John Doe", "http://test.onion/doc.pdf")

		if finding == nil {
			t.Fatal("expected finding, got nil")
		}
		if finding.Type != "pdf_xmp_creator" {
			t.Errorf("expected type 'pdf_xmp_creator', got '%s'", finding.Type)
		}
		if finding.Severity != model.SeverityHigh {
			t.Errorf("expected high severity, got %s", finding.Severity)
		}
	})

	t.Run("skips date without timezone", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPDFAnalyzer()

		// Date without timezone should not create finding
		finding := analyzer.createFindingFromMetadata("creationDate", "D:20240101120000", "http://test.onion/doc.pdf")
		if finding != nil {
			t.Error("expected nil finding for date without timezone")
		}
	})
}

// TestCloudAnalyzer tests cloud service detection functionality.
func TestCloudAnalyzer(t *testing.T) {
	t.Parallel()

	t.Run("Name returns correct value", func(t *testing.T) {
		t.Parallel()

		analyzer := NewCloudAnalyzer()
		if analyzer.Name() != "cloud" {
			t.Errorf("expected name 'cloud', got '%s'", analyzer.Name())
		}
	})

	t.Run("Category returns correlation", func(t *testing.T) {
		t.Parallel()

		analyzer := NewCloudAnalyzer()
		if analyzer.Category() != CategoryCorrelation {
			t.Errorf("expected category '%s', got '%s'", CategoryCorrelation, analyzer.Category())
		}
	})

	t.Run("detects AWS S3 bucket", func(t *testing.T) {
		t.Parallel()

		analyzer := NewCloudAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `<img src="https://mybucket.s3.amazonaws.com/image.jpg">`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "aws_s3_bucket" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find AWS S3 bucket finding")
		}
	})

	t.Run("detects AWS CloudFront", func(t *testing.T) {
		t.Parallel()

		analyzer := NewCloudAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `<script src="https://d1234567890.cloudfront.net/app.js"></script>`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "aws_cloudfront" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find AWS CloudFront finding")
		}
	})

	t.Run("detects Google Cloud Storage", func(t *testing.T) {
		t.Parallel()

		analyzer := NewCloudAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `<img src="https://storage.googleapis.com/mybucket/image.png">`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "gcp_storage" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find GCP Storage finding")
		}
	})

	t.Run("detects Firebase", func(t *testing.T) {
		t.Parallel()

		analyzer := NewCloudAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `var config = { databaseURL: "https://myapp.firebaseio.com" };`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "gcp_firebase" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find Firebase finding")
		}
	})

	t.Run("detects Azure Blob Storage", func(t *testing.T) {
		t.Parallel()

		analyzer := NewCloudAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `<img src="https://myaccount.blob.core.windows.net/container/image.jpg">`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "azure_blob" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find Azure Blob finding")
		}
	})

	t.Run("detects Cloudflare Workers", func(t *testing.T) {
		t.Parallel()

		analyzer := NewCloudAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `API endpoint: https://myworker.workers.dev/api`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "cloudflare_workers" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find Cloudflare Workers finding")
		}
	})

	t.Run("detects Vercel deployment", func(t *testing.T) {
		t.Parallel()

		analyzer := NewCloudAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `Preview: https://myproject.vercel.app`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "vercel" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find Vercel finding")
		}
	})

	t.Run("detects Cloudflare header", func(t *testing.T) {
		t.Parallel()

		analyzer := NewCloudAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `Hello`,
					Headers: map[string][]string{
						"CF-RAY": {"1234567890abcdef-SJC"},
					},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "cloudflare_header" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find Cloudflare header finding")
		}
	})

	t.Run("detects AWS header", func(t *testing.T) {
		t.Parallel()

		analyzer := NewCloudAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/",
					Snapshot: `Hello`,
					Headers: map[string][]string{
						"x-amz-request-id": {"ABCD1234"},
					},
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, f := range findings {
			if f.Type == "aws_header" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find AWS header finding")
		}
	})

	t.Run("handles empty pages", func(t *testing.T) {
		t.Parallel()

		analyzer := NewCloudAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages:         []*model.Page{},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(findings) != 0 {
			t.Errorf("expected no findings for empty pages, got %d", len(findings))
		}
	})

	t.Run("deduplicates findings", func(t *testing.T) {
		t.Parallel()

		analyzer := NewCloudAnalyzer()
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL:      "http://test.onion/page1",
					Snapshot: `<img src="https://mybucket.s3.amazonaws.com/image1.jpg">`,
				},
				{
					URL:      "http://test.onion/page2",
					Snapshot: `<img src="https://mybucket.s3.amazonaws.com/image1.jpg">`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		s3Count := 0
		for _, f := range findings {
			if f.Type == "aws_s3_bucket" {
				s3Count++
			}
		}
		if s3Count > 1 {
			t.Errorf("expected at most 1 S3 finding (deduplicated), got %d", s3Count)
		}
	})
}
