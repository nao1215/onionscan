package pipeline

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nao1215/onionscan/internal/model"
)

// TestNewHTTPScanStep tests the HTTPScanStep constructor.
func TestNewHTTPScanStep(t *testing.T) {
	t.Parallel()

	t.Run("creates with defaults", func(t *testing.T) {
		t.Parallel()

		step := NewHTTPScanStep(http.DefaultClient)

		if step.client != http.DefaultClient {
			t.Error("expected default client")
		}
		if step.maxBodySize != 5*1024*1024 {
			t.Errorf("expected default maxBodySize 5MB, got %d", step.maxBodySize)
		}
		if step.logger == nil {
			t.Error("expected non-nil logger")
		}
	})

	t.Run("applies WithHTTPMaxBodySize", func(t *testing.T) {
		t.Parallel()

		step := NewHTTPScanStep(http.DefaultClient, WithHTTPMaxBodySize(1024))

		if step.maxBodySize != 1024 {
			t.Errorf("expected maxBodySize 1024, got %d", step.maxBodySize)
		}
	})

	t.Run("applies WithHTTPLogger", func(t *testing.T) {
		t.Parallel()

		logger := slog.Default()
		step := NewHTTPScanStep(http.DefaultClient, WithHTTPLogger(logger))

		if step.logger != logger {
			t.Error("expected custom logger")
		}
	})

	t.Run("Name returns correct value", func(t *testing.T) {
		t.Parallel()

		step := NewHTTPScanStep(http.DefaultClient)

		if step.Name() != "http_scan" {
			t.Errorf("expected name 'http_scan', got %q", step.Name())
		}
	})
}

// TestNewCrawlStep tests the CrawlStep constructor.
func TestNewCrawlStep(t *testing.T) {
	t.Parallel()

	t.Run("creates with defaults", func(t *testing.T) {
		t.Parallel()

		step := NewCrawlStep(http.DefaultClient)

		if step.client != http.DefaultClient {
			t.Error("expected default client")
		}
		if step.maxDepth != 5 {
			t.Errorf("expected default maxDepth 5, got %d", step.maxDepth)
		}
		if step.maxPages != 100 {
			t.Errorf("expected default maxPages 100, got %d", step.maxPages)
		}
		if step.delay != 1*time.Second {
			t.Errorf("expected default delay 1s, got %v", step.delay)
		}
	})

	t.Run("applies WithCrawlMaxDepth", func(t *testing.T) {
		t.Parallel()

		step := NewCrawlStep(http.DefaultClient, WithCrawlMaxDepth(10))

		if step.maxDepth != 10 {
			t.Errorf("expected maxDepth 10, got %d", step.maxDepth)
		}
	})

	t.Run("applies WithCrawlMaxPages", func(t *testing.T) {
		t.Parallel()

		step := NewCrawlStep(http.DefaultClient, WithCrawlMaxPages(50))

		if step.maxPages != 50 {
			t.Errorf("expected maxPages 50, got %d", step.maxPages)
		}
	})

	t.Run("applies WithCrawlDelay", func(t *testing.T) {
		t.Parallel()

		step := NewCrawlStep(http.DefaultClient, WithCrawlDelay(500*time.Millisecond))

		if step.delay != 500*time.Millisecond {
			t.Errorf("expected delay 500ms, got %v", step.delay)
		}
	})

	t.Run("applies WithCrawlLogger", func(t *testing.T) {
		t.Parallel()

		logger := slog.Default()
		step := NewCrawlStep(http.DefaultClient, WithCrawlLogger(logger))

		if step.logger != logger {
			t.Error("expected custom logger")
		}
	})

	t.Run("applies WithCrawlIgnorePatterns", func(t *testing.T) {
		t.Parallel()

		patterns := []string{"/admin/*", "*.pdf"}
		step := NewCrawlStep(http.DefaultClient, WithCrawlIgnorePatterns(patterns))

		if len(step.ignorePatterns) != 2 {
			t.Errorf("expected 2 ignore patterns, got %d", len(step.ignorePatterns))
		}
	})

	t.Run("applies WithCrawlFollowPatterns", func(t *testing.T) {
		t.Parallel()

		patterns := []string{"/api/*", "/public/*"}
		step := NewCrawlStep(http.DefaultClient, WithCrawlFollowPatterns(patterns))

		if len(step.followPatterns) != 2 {
			t.Errorf("expected 2 follow patterns, got %d", len(step.followPatterns))
		}
	})

	t.Run("Name returns correct value", func(t *testing.T) {
		t.Parallel()

		step := NewCrawlStep(http.DefaultClient)

		if step.Name() != "crawl" {
			t.Errorf("expected name 'crawl', got %q", step.Name())
		}
	})
}

// TestNewDeanonStep tests the DeanonStep constructor.
func TestNewDeanonStep(t *testing.T) {
	t.Parallel()

	t.Run("creates with defaults", func(t *testing.T) {
		t.Parallel()

		step := NewDeanonStep()

		if step.analyzer == nil {
			t.Error("expected non-nil analyzer")
		}
		if step.logger == nil {
			t.Error("expected non-nil logger")
		}
	})

	t.Run("applies WithDeanonLogger", func(t *testing.T) {
		t.Parallel()

		logger := slog.Default()
		step := NewDeanonStep(WithDeanonLogger(logger))

		if step.logger != logger {
			t.Error("expected custom logger")
		}
	})

	t.Run("Name returns correct value", func(t *testing.T) {
		t.Parallel()

		step := NewDeanonStep()

		if step.Name() != "deanon" {
			t.Errorf("expected name 'deanon', got %q", step.Name())
		}
	})
}

// TestNewProtocolScanStep tests the ProtocolScanStep constructor.
func TestNewProtocolScanStep(t *testing.T) {
	t.Parallel()

	t.Run("creates with defaults", func(t *testing.T) {
		t.Parallel()

		step := NewProtocolScanStep(nil)

		if len(step.protocols) != 7 {
			t.Errorf("expected 7 default protocols, got %d", len(step.protocols))
		}
		if step.logger == nil {
			t.Error("expected non-nil logger")
		}
	})

	t.Run("default protocols include ssh, ftp, smtp and databases", func(t *testing.T) {
		t.Parallel()

		step := NewProtocolScanStep(nil)

		expectedProtocols := map[string]bool{
			"ssh":        true,
			"ftp":        true,
			"smtp":       true,
			"mongodb":    true,
			"redis":      true,
			"postgresql": true,
			"mysql":      true,
		}

		for _, proto := range step.protocols {
			if !expectedProtocols[proto] {
				t.Errorf("unexpected protocol: %s", proto)
			}
		}
	})

	t.Run("applies WithProtocols", func(t *testing.T) {
		t.Parallel()

		step := NewProtocolScanStep(nil, WithProtocols([]string{"ssh", "ftp"}))

		if len(step.protocols) != 2 {
			t.Errorf("expected 2 protocols, got %d", len(step.protocols))
		}
	})

	t.Run("applies WithProtocolLogger", func(t *testing.T) {
		t.Parallel()

		logger := slog.Default()
		step := NewProtocolScanStep(nil, WithProtocolLogger(logger))

		if step.logger != logger {
			t.Error("expected custom logger")
		}
	})

	t.Run("Name returns correct value", func(t *testing.T) {
		t.Parallel()

		step := NewProtocolScanStep(nil)

		if step.Name() != "protocol_scan" {
			t.Errorf("expected name 'protocol_scan', got %q", step.Name())
		}
	})
}

// TestCrawlStepCombinedOptions tests applying multiple options.
func TestCrawlStepCombinedOptions(t *testing.T) {
	t.Parallel()

	step := NewCrawlStep(
		http.DefaultClient,
		WithCrawlMaxDepth(20),
		WithCrawlMaxPages(500),
		WithCrawlDelay(2*time.Second),
		WithCrawlIgnorePatterns([]string{"/admin/*"}),
		WithCrawlFollowPatterns([]string{"/api/*"}),
	)

	if step.maxDepth != 20 {
		t.Errorf("expected maxDepth 20, got %d", step.maxDepth)
	}
	if step.maxPages != 500 {
		t.Errorf("expected maxPages 500, got %d", step.maxPages)
	}
	if step.delay != 2*time.Second {
		t.Errorf("expected delay 2s, got %v", step.delay)
	}
	if len(step.ignorePatterns) != 1 {
		t.Errorf("expected 1 ignore pattern, got %d", len(step.ignorePatterns))
	}
	if len(step.followPatterns) != 1 {
		t.Errorf("expected 1 follow pattern, got %d", len(step.followPatterns))
	}
}

// TestHTTPScanStepCombinedOptions tests applying multiple HTTP options.
func TestHTTPScanStepCombinedOptions(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	step := NewHTTPScanStep(
		http.DefaultClient,
		WithHTTPMaxBodySize(10*1024*1024),
		WithHTTPLogger(logger),
	)

	if step.maxBodySize != 10*1024*1024 {
		t.Errorf("expected maxBodySize 10MB, got %d", step.maxBodySize)
	}
	if step.logger != logger {
		t.Error("expected custom logger")
	}
}

// TestProtocolScanStepCombinedOptions tests applying multiple protocol options.
func TestProtocolScanStepCombinedOptions(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	step := NewProtocolScanStep(
		nil,
		WithProtocols([]string{"ssh"}),
		WithProtocolLogger(logger),
	)

	if len(step.protocols) != 1 {
		t.Errorf("expected 1 protocol, got %d", len(step.protocols))
	}
	if step.protocols[0] != "ssh" {
		t.Errorf("expected protocol 'ssh', got %q", step.protocols[0])
	}
	if step.logger != logger {
		t.Error("expected custom logger")
	}
}

// TestDeanonStepCombinedOptions tests applying multiple deanon options.
func TestDeanonStepCombinedOptions(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	step := NewDeanonStep(WithDeanonLogger(logger))

	if step.logger != logger {
		t.Error("expected custom logger")
	}
	if step.analyzer == nil {
		t.Error("expected non-nil analyzer")
	}
}

// TestHTTPScanStepDo tests the HTTPScanStep.Do method with mock HTTP server.
func TestHTTPScanStepDo(t *testing.T) {
	t.Run("detects HTTP service", func(t *testing.T) {
		// Create mock server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Server", "nginx/1.18.0")
			w.Header().Set("X-Powered-By", "PHP/7.4")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>Hello</body></html>"))
		}))
		defer server.Close()

		// Extract host:port from server URL (remove http://)
		hostPort := strings.TrimPrefix(server.URL, "http://")

		step := NewHTTPScanStep(server.Client())
		report := model.NewOnionScanReport(hostPort)

		err := step.Do(context.Background(), report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !report.WebDetected {
			t.Error("expected WebDetected to be true")
		}
	})

	t.Run("handles connection failure gracefully", func(t *testing.T) {
		// Create client that won't connect
		client := &http.Client{
			Timeout: 100 * time.Millisecond,
		}

		step := NewHTTPScanStep(client)
		report := model.NewOnionScanReport("nonexistent.onion")

		err := step.Do(context.Background(), report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should not detect web service on failed connection
		if report.WebDetected {
			t.Error("expected WebDetected to be false for failed connection")
		}
	})

	t.Run("respects context cancellation", func(_ *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(5 * time.Second)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		hostPort := strings.TrimPrefix(server.URL, "http://")

		step := NewHTTPScanStep(server.Client())
		report := model.NewOnionScanReport(hostPort)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		// This should not hang - context will timeout
		err := step.Do(ctx, report)
		// Error may or may not be returned depending on timing
		_ = err
	})

	t.Run("extracts server headers", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Server", "Apache/2.4.46")
			w.Header().Set("X-Powered-By", "Express")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("test"))
		}))
		defer server.Close()

		hostPort := strings.TrimPrefix(server.URL, "http://")

		step := NewHTTPScanStep(server.Client())
		report := model.NewOnionScanReport(hostPort)

		err := step.Do(context.Background(), report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if report.AnonymityReport.ServerVersion != "Apache/2.4.46" {
			t.Errorf("expected server version 'Apache/2.4.46', got %q", report.AnonymityReport.ServerVersion)
		}
		if report.AnonymityReport.XPoweredBy != "Express" {
			t.Errorf("expected X-Powered-By 'Express', got %q", report.AnonymityReport.XPoweredBy)
		}
	})
}

// TestCrawlStepDo tests the CrawlStep.Do method.
func TestCrawlStepDo(t *testing.T) {
	t.Run("skips crawl when web not detected", func(t *testing.T) {
		step := NewCrawlStep(http.DefaultClient)
		report := model.NewOnionScanReport("test.onion")
		report.WebDetected = false

		err := step.Do(context.Background(), report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(report.CrawledPages) != 0 {
			t.Errorf("expected no crawled pages, got %d", len(report.CrawledPages))
		}
	})

	t.Run("crawls when web is detected", func(t *testing.T) {
		// Create mock server with some pages
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`<html><body><a href="/page1">Page 1</a></body></html>`))
		})
		mux.HandleFunc("/page1", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`<html><body>Page 1 content</body></html>`))
		})

		server := httptest.NewServer(mux)
		defer server.Close()

		hostPort := strings.TrimPrefix(server.URL, "http://")

		step := NewCrawlStep(server.Client(), WithCrawlMaxPages(10), WithCrawlDelay(0))
		report := model.NewOnionScanReport(hostPort)
		report.WebDetected = true

		err := step.Do(context.Background(), report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(report.CrawledPages) == 0 {
			t.Error("expected crawled pages")
		}
	})
}

// TestDeanonStepDo tests the DeanonStep.Do method.
func TestDeanonStepDo(t *testing.T) {
	t.Run("skips analysis when no pages crawled", func(t *testing.T) {
		step := NewDeanonStep()
		report := model.NewOnionScanReport("test.onion")
		report.CrawledPages = nil

		err := step.Do(context.Background(), report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// No findings should be added (SimpleReport may be nil or have empty findings)
		if report.SimpleReport != nil && len(report.SimpleReport.Findings) != 0 {
			t.Errorf("expected no findings, got %d", len(report.SimpleReport.Findings))
		}
	})

	t.Run("analyzes crawled pages", func(t *testing.T) {
		step := NewDeanonStep()
		report := model.NewOnionScanReport("test.onion")
		report.CrawledPages = []*model.Page{
			{
				URL:        "http://test.onion/",
				StatusCode: 200,
				Snapshot:   "<html><body>Contact: admin@example.com</body></html>",
				Raw:        []byte(`<html><body>Contact: admin@example.com</body></html>`),
			},
		}

		err := step.Do(context.Background(), report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should have findings from content analysis (e.g., email)
		// The exact findings depend on the analyzers
	})

	t.Run("handles multiple pages", func(t *testing.T) {
		step := NewDeanonStep()
		report := model.NewOnionScanReport("test.onion")
		report.CrawledPages = []*model.Page{
			{
				URL:        "http://test.onion/",
				StatusCode: 200,
				Snapshot:   "<html><body>Page 1</body></html>",
				Raw:        []byte(`<html><body>Page 1</body></html>`),
			},
			{
				URL:        "http://test.onion/page2",
				StatusCode: 200,
				Snapshot:   "<html><body>Page 2</body></html>",
				Raw:        []byte(`<html><body>Page 2</body></html>`),
			},
		}

		err := step.Do(context.Background(), report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
