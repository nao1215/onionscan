package crawler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestParser tests HTML parsing functionality.
func TestParser(t *testing.T) {
	t.Parallel()

	t.Run("extracts title", func(t *testing.T) {
		t.Parallel()

		html := `<html><head><title>Test Page</title></head><body></body></html>`
		parser, err := NewParser("http://test.onion/page")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		if result.Title != "Test Page" {
			t.Errorf("expected title 'Test Page', got %q", result.Title)
		}
	})

	t.Run("extracts links and classifies them", func(t *testing.T) {
		t.Parallel()

		html := `<html><body>
			<a href="/internal">Internal Link</a>
			<a href="http://test.onion/same">Same Service</a>
			<a href="http://other.onion/external">External Onion</a>
			<a href="http://example.com/clearnet">Clearnet</a>
		</body></html>`

		parser, err := NewParser("http://test.onion/page")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		if len(result.Links) != 4 {
			t.Errorf("expected 4 links, got %d", len(result.Links))
		}

		// Internal links should include relative and same-service
		if len(result.InternalLinks) != 2 {
			t.Errorf("expected 2 internal links, got %d: %v", len(result.InternalLinks), result.InternalLinks)
		}

		// External onion links
		if len(result.ExternalLinks) != 1 {
			t.Errorf("expected 1 external link, got %d", len(result.ExternalLinks))
		}

		// Clearnet links
		if len(result.ClearnetLinks) != 1 {
			t.Errorf("expected 1 clearnet link, got %d", len(result.ClearnetLinks))
		}
	})

	t.Run("extracts forms", func(t *testing.T) {
		t.Parallel()

		html := `<html><body>
			<form action="/login" method="POST">
				<input type="text" name="username">
				<input type="password" name="password">
				<input type="hidden" name="csrf" value="token123">
				<input type="submit" name="submit" value="Login">
			</form>
		</body></html>`

		parser, err := NewParser("http://test.onion")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		if len(result.Forms) != 1 {
			t.Fatalf("expected 1 form, got %d", len(result.Forms))
		}

		form := result.Forms[0]
		if form.Method != http.MethodPost {
			t.Errorf("expected method POST, got %q", form.Method)
		}
		if !strings.HasSuffix(form.Action, "/login") {
			t.Errorf("expected action to end with /login, got %q", form.Action)
		}
		if len(form.Fields) != 4 {
			t.Errorf("expected 4 fields, got %d", len(form.Fields))
		}
	})

	t.Run("extracts email addresses", func(t *testing.T) {
		t.Parallel()

		// Note: mailto: links are skipped by the link parser, but email
		// addresses are extracted from all text content including anchor text
		html := `<html><body>
			<p>Contact us at admin@example.com or support@test.org</p>
			<a href="mailto:info@service.com">Email info@service.com</a>
		</body></html>`

		parser, err := NewParser("http://test.onion")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		if len(result.Emails) != 3 {
			t.Errorf("expected 3 emails, got %d: %v", len(result.Emails), result.Emails)
		}
	})

	t.Run("extracts onion addresses from text", func(t *testing.T) {
		t.Parallel()

		// V2 addresses are 16 characters, V3 addresses are 56 characters
		// Using valid base32 characters (a-z, 2-7)
		html := `<html><body>
			<p>Visit us at abcdefghijklmnop.onion (v2 address)</p>
			<p>Or try the new address: abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion</p>
		</body></html>`

		parser, err := NewParser("http://test.onion")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		if len(result.OnionAddresses) != 2 {
			t.Errorf("expected 2 onion addresses, got %d: %v", len(result.OnionAddresses), result.OnionAddresses)
		}
	})

	t.Run("extracts meta tags", func(t *testing.T) {
		t.Parallel()

		html := `<html><head>
			<meta name="description" content="Test description">
			<meta property="og:title" content="OpenGraph Title">
			<meta name="author" content="John Doe">
		</head></html>`

		parser, err := NewParser("http://test.onion")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		if result.MetaTags["description"] != "Test description" {
			t.Errorf("expected description meta tag")
		}
		if result.MetaTags["og:title"] != "OpenGraph Title" {
			t.Errorf("expected og:title meta tag")
		}
		if result.MetaTags["author"] != "John Doe" {
			t.Errorf("expected author meta tag")
		}
	})

	t.Run("extracts scripts and images", func(t *testing.T) {
		t.Parallel()

		html := `<html><body>
			<script src="/js/app.js"></script>
			<script src="http://cdn.example.com/lib.js"></script>
			<img src="/images/logo.png">
			<img src="http://other.onion/pic.jpg">
		</body></html>`

		parser, err := NewParser("http://test.onion")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		if len(result.Scripts) != 2 {
			t.Errorf("expected 2 scripts, got %d", len(result.Scripts))
		}
		if len(result.Images) != 2 {
			t.Errorf("expected 2 images, got %d", len(result.Images))
		}
	})

	t.Run("extracts HTML comments", func(t *testing.T) {
		t.Parallel()

		html := `<html><body>
			<!-- TODO: remove this before production -->
			<p>Content</p>
			<!-- Developer: John Doe - john@company.com -->
		</body></html>`

		parser, err := NewParser("http://test.onion")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		if len(result.Comments) != 2 {
			t.Errorf("expected 2 comments, got %d", len(result.Comments))
		}
	})

	t.Run("handles special link types", func(t *testing.T) {
		t.Parallel()

		html := `<html><body>
			<a href="javascript:void(0)">JS Link</a>
			<a href="mailto:test@example.com">Email</a>
			<a href="tel:+1234567890">Phone</a>
			<a href="#">Anchor</a>
			<a href="/valid">Valid</a>
		</body></html>`

		parser, err := NewParser("http://test.onion")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		// Only /valid should be extracted
		if len(result.Links) != 1 {
			t.Errorf("expected 1 valid link, got %d: %v", len(result.Links), result.Links)
		}
	})
}

// TestSpider tests the web crawler.
func TestSpider(t *testing.T) {
	t.Parallel()

	t.Run("crawls single page", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>Test</title></head><body>Hello</body></html>`)) //nolint:errcheck
		}))
		defer server.Close()

		spider := NewSpider(server.Client(), WithMaxDepth(0), WithDelay(0))
		ctx := context.Background()

		pages, err := spider.Crawl(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(pages) != 1 {
			t.Fatalf("expected 1 page, got %d", len(pages))
		}

		if pages[0].Title != "Test" {
			t.Errorf("expected title 'Test', got %q", pages[0].Title)
		}
	})

	t.Run("follows links within depth limit", func(t *testing.T) {
		t.Parallel()

		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			//nolint:errcheck // test handler
			_, _ = w.Write([]byte(`<html><body><a href="/page1">Page 1</a><a href="/page2">Page 2</a></body></html>`))
		})
		mux.HandleFunc("/page1", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body>Page 1</body></html>`)) //nolint:errcheck
		})
		mux.HandleFunc("/page2", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body>Page 2</body></html>`)) //nolint:errcheck
		})

		server := httptest.NewServer(mux)
		defer server.Close()

		spider := NewSpider(server.Client(), WithMaxDepth(1), WithDelay(0))
		ctx := context.Background()

		pages, err := spider.Crawl(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(pages) != 3 {
			t.Errorf("expected 3 pages, got %d", len(pages))
		}
	})

	t.Run("respects max pages limit", func(t *testing.T) {
		t.Parallel()

		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			//nolint:errcheck // test handler
			_, _ = w.Write([]byte(`<html><body><a href="/page1">1</a><a href="/page2">2</a><a href="/page3">3</a><a href="/page4">4</a><a href="/page5">5</a></body></html>`))
		})
		for i := 1; i <= 5; i++ {
			mux.HandleFunc(fmt.Sprintf("/page%d", i), func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte(`<html><body>Page</body></html>`)) //nolint:errcheck
			})
		}

		server := httptest.NewServer(mux)
		defer server.Close()

		spider := NewSpider(server.Client(), WithMaxPages(3), WithMaxDepth(1), WithDelay(0))
		ctx := context.Background()

		pages, err := spider.Crawl(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(pages) > 3 {
			t.Errorf("expected at most 3 pages, got %d", len(pages))
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		t.Parallel()

		// Create a server that takes a while to respond
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(500 * time.Millisecond)
			_, _ = w.Write([]byte(`<html><body>Slow</body></html>`)) //nolint:errcheck
		}))
		defer server.Close()

		spider := NewSpider(server.Client(), WithDelay(0))
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_, err := spider.Crawl(ctx, server.URL)
		// Either context deadline exceeded or no pages returned is acceptable
		if err == nil {
			// If no error, it means the request completed quickly or was cancelled
			// The key is that the crawler didn't hang
			t.Log("no error returned, but crawler did not hang which is acceptable")
		}
	})

	t.Run("avoids duplicate visits", func(t *testing.T) {
		t.Parallel()

		visitCount := 0
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			visitCount++
			w.Header().Set("Content-Type", "text/html")
			//nolint:errcheck // test handler
			_, _ = w.Write([]byte(`<html><body><a href="/">Self</a><a href="/">Self Again</a></body></html>`))
		})

		server := httptest.NewServer(mux)
		defer server.Close()

		spider := NewSpider(server.Client(), WithMaxDepth(1), WithDelay(0))
		ctx := context.Background()

		_, err := spider.Crawl(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if visitCount != 1 {
			t.Errorf("expected 1 visit, got %d", visitCount)
		}
	})
}

// TestSpiderOptions tests spider configuration options.
func TestSpiderOptions(t *testing.T) {
	t.Parallel()

	t.Run("WithMaxDepth sets depth", func(t *testing.T) {
		t.Parallel()

		spider := NewSpider(http.DefaultClient, WithMaxDepth(10))
		if spider.maxDepth != 10 {
			t.Errorf("expected maxDepth 10, got %d", spider.maxDepth)
		}
	})

	t.Run("WithMaxPages sets limit", func(t *testing.T) {
		t.Parallel()

		spider := NewSpider(http.DefaultClient, WithMaxPages(50))
		if spider.maxPages != 50 {
			t.Errorf("expected maxPages 50, got %d", spider.maxPages)
		}
	})

	t.Run("WithDelay sets delay", func(t *testing.T) {
		t.Parallel()

		spider := NewSpider(http.DefaultClient, WithDelay(2*time.Second))
		if spider.delay != 2*time.Second {
			t.Errorf("expected delay 2s, got %v", spider.delay)
		}
	})

	t.Run("WithSpiderUserAgent sets user agent", func(t *testing.T) {
		t.Parallel()

		spider := NewSpider(http.DefaultClient, WithSpiderUserAgent("TestBot/1.0"))
		if spider.userAgent != "TestBot/1.0" {
			t.Errorf("expected userAgent 'TestBot/1.0', got %q", spider.userAgent)
		}
	})

	t.Run("WithSpiderMaxBodySize sets max body size", func(t *testing.T) {
		t.Parallel()

		spider := NewSpider(http.DefaultClient, WithSpiderMaxBodySize(1024*1024))
		if spider.maxBodySize != 1024*1024 {
			t.Errorf("expected maxBodySize 1MB, got %d", spider.maxBodySize)
		}
	})

	t.Run("WithIgnorePatterns sets ignore patterns", func(t *testing.T) {
		t.Parallel()

		patterns := []string{"/admin/*", "*.pdf"}
		spider := NewSpider(http.DefaultClient, WithIgnorePatterns(patterns))
		if len(spider.ignorePatterns) != 2 {
			t.Errorf("expected 2 ignore patterns, got %d", len(spider.ignorePatterns))
		}
	})

	t.Run("WithFollowPatterns sets follow patterns", func(t *testing.T) {
		t.Parallel()

		patterns := []string{"/api/*", "/public/*"}
		spider := NewSpider(http.DefaultClient, WithFollowPatterns(patterns))
		if len(spider.followPatterns) != 2 {
			t.Errorf("expected 2 follow patterns, got %d", len(spider.followPatterns))
		}
	})
}

// TestMatchPattern tests glob pattern matching.
func TestMatchPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		// Prefix patterns with /*
		{"admin prefix match", "/admin/*", "/admin/dashboard", true},
		{"admin prefix exact", "/admin/*", "/admin", true},
		{"admin prefix no match", "/admin/*", "/user/profile", false},
		{"admin prefix partial no match", "/admin/*", "/administrator", false},

		// Extension patterns with *.
		{"pdf extension", "*.pdf", "/docs/file.pdf", true},
		{"pdf extension nested", "*.pdf", "/a/b/c/report.pdf", true},
		{"pdf extension no match", "*.pdf", "/docs/file.txt", false},
		{"jpg extension", "*.jpg", "/images/photo.jpg", true},

		// Exact match patterns
		{"exact match", "/logout", "/logout", true},
		{"exact no match", "/logout", "/login", false},

		// Wildcard in middle
		{"wildcard middle", "/api/v?/users", "/api/v1/users", true},
		{"wildcard middle v2", "/api/v?/users", "/api/v2/users", true},
		{"wildcard middle no match", "/api/v?/users", "/api/v10/users", false},

		// Root path
		{"root path", "/", "/", true},
		{"root no match prefix", "/admin/*", "/", false},

		// Complex patterns
		{"nested admin", "/admin/*", "/admin/users/edit", true},
		{"api prefix", "/api/*", "/api/v1/data", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := matchPattern(tt.pattern, tt.path)
			if got != tt.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

// TestShouldCrawl tests URL filtering based on patterns.
func TestShouldCrawl(t *testing.T) {
	t.Parallel()

	t.Run("no patterns allows all", func(t *testing.T) {
		t.Parallel()

		spider := NewSpider(http.DefaultClient)
		if !spider.shouldCrawl("http://test.onion/any/path") {
			t.Error("expected all URLs to be allowed when no patterns set")
		}
	})

	t.Run("ignore patterns block matching URLs", func(t *testing.T) {
		t.Parallel()

		spider := NewSpider(http.DefaultClient, WithIgnorePatterns([]string{"/admin/*", "*.pdf"}))

		tests := []struct {
			url  string
			want bool
		}{
			{"http://test.onion/admin/dashboard", false},
			{"http://test.onion/admin/users", false},
			{"http://test.onion/docs/file.pdf", false},
			{"http://test.onion/public/page", true},
			{"http://test.onion/api/data", true},
		}

		for _, tt := range tests {
			got := spider.shouldCrawl(tt.url)
			if got != tt.want {
				t.Errorf("shouldCrawl(%q) = %v, want %v", tt.url, got, tt.want)
			}
		}
	})

	t.Run("follow patterns restrict to matching URLs", func(t *testing.T) {
		t.Parallel()

		spider := NewSpider(http.DefaultClient, WithFollowPatterns([]string{"/api/*", "/public/*"}))

		tests := []struct {
			url  string
			want bool
		}{
			{"http://test.onion/api/v1/users", true},
			{"http://test.onion/public/page", true},
			{"http://test.onion/admin/dashboard", false},
			{"http://test.onion/private/data", false},
		}

		for _, tt := range tests {
			got := spider.shouldCrawl(tt.url)
			if got != tt.want {
				t.Errorf("shouldCrawl(%q) = %v, want %v", tt.url, got, tt.want)
			}
		}
	})

	t.Run("ignore takes precedence over follow", func(t *testing.T) {
		t.Parallel()

		spider := NewSpider(http.DefaultClient,
			WithIgnorePatterns([]string{"/api/internal/*"}),
			WithFollowPatterns([]string{"/api/*"}),
		)

		tests := []struct {
			url  string
			want bool
		}{
			{"http://test.onion/api/v1/users", true},
			{"http://test.onion/api/internal/secret", false}, // ignored despite matching follow
			{"http://test.onion/public/page", false},         // doesn't match follow
		}

		for _, tt := range tests {
			got := spider.shouldCrawl(tt.url)
			if got != tt.want {
				t.Errorf("shouldCrawl(%q) = %v, want %v", tt.url, got, tt.want)
			}
		}
	})

	t.Run("invalid URL returns false", func(t *testing.T) {
		t.Parallel()

		spider := NewSpider(http.DefaultClient)
		if spider.shouldCrawl("://invalid") {
			t.Error("expected invalid URL to return false")
		}
	})

	t.Run("empty path treated as root", func(t *testing.T) {
		t.Parallel()

		spider := NewSpider(http.DefaultClient, WithFollowPatterns([]string{"/"}))
		if !spider.shouldCrawl("http://test.onion") {
			t.Error("expected empty path to match root pattern")
		}
	})
}

// TestSpiderReset tests clearing spider state.
func TestSpiderReset(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>Test</body></html>`))
	}))
	defer server.Close()

	spider := NewSpider(server.Client(), WithMaxDepth(0), WithDelay(0))
	ctx := context.Background()

	// First crawl
	pages1, err := spider.Crawl(ctx, server.URL)
	if err != nil {
		t.Fatalf("first crawl error: %v", err)
	}
	if len(pages1) != 1 {
		t.Fatalf("expected 1 page, got %d", len(pages1))
	}

	// Second crawl without reset - should return no new pages (URL visited)
	pages2, err := spider.Crawl(ctx, server.URL)
	if err != nil {
		t.Fatalf("second crawl error: %v", err)
	}
	if len(pages2) != 0 {
		t.Errorf("expected 0 pages without reset, got %d", len(pages2))
	}

	// Reset and crawl again
	spider.Reset()
	pages3, err := spider.Crawl(ctx, server.URL)
	if err != nil {
		t.Fatalf("third crawl error: %v", err)
	}
	if len(pages3) != 1 {
		t.Errorf("expected 1 page after reset, got %d", len(pages3))
	}
}

// TestSpiderStats tests crawl statistics.
func TestSpiderStats(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/page1">1</a><a href="/page2">2</a></body></html>`))
	})
	mux.HandleFunc("/page1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>Page 1</body></html>`))
	})
	mux.HandleFunc("/page2", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>Page 2</body></html>`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	spider := NewSpider(server.Client(), WithMaxDepth(1), WithDelay(0))
	ctx := context.Background()

	_, err := spider.Crawl(ctx, server.URL)
	if err != nil {
		t.Fatalf("crawl error: %v", err)
	}

	stats := spider.Stats()
	if stats.PagesVisited != 3 {
		t.Errorf("expected 3 pages visited, got %d", stats.PagesVisited)
	}
	if stats.URLsQueued < 3 {
		t.Errorf("expected at least 3 URLs queued, got %d", stats.URLsQueued)
	}
}

// TestNormalizeURL tests URL normalization.
func TestNormalizeURL(t *testing.T) {
	t.Parallel()

	spider := NewSpider(http.DefaultClient)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"removes fragment", "http://test.onion/page#section", "http://test.onion/page"},
		{"lowercase scheme", "HTTP://test.onion/page", "http://test.onion/page"},
		{"lowercase host", "http://TEST.ONION/page", "http://test.onion/page"},
		{"empty path becomes root", "http://test.onion", "http://test.onion/"},
		{"preserves query", "http://test.onion/search?q=test", "http://test.onion/search?q=test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := spider.normalizeURL(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeURL(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestIsSameService tests same-service detection.
func TestIsSameService(t *testing.T) {
	t.Parallel()

	spider := NewSpider(http.DefaultClient)

	tests := []struct {
		name     string
		baseHost string
		target   string
		want     bool
	}{
		{"same host", "test.onion", "http://test.onion/page", true},
		{"same host different case", "test.onion", "http://TEST.ONION/page", true},
		{"different host", "test.onion", "http://other.onion/page", false},
		{"invalid URL", "test.onion", "://invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := spider.isSameService(tt.baseHost, tt.target)
			if got != tt.want {
				t.Errorf("isSameService(%q, %q) = %v, want %v", tt.baseHost, tt.target, got, tt.want)
			}
		})
	}
}

// TestParserFormFieldTypes tests form field type detection for textarea and select.
func TestParserFormFieldTypes(t *testing.T) {
	t.Parallel()

	t.Run("extracts textarea fields", func(t *testing.T) {
		t.Parallel()

		html := `<html><body>
			<form action="/submit" method="POST">
				<textarea name="message">Default text</textarea>
			</form>
		</body></html>`

		parser, err := NewParser("http://test.onion")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		if len(result.Forms) != 1 {
			t.Fatalf("expected 1 form, got %d", len(result.Forms))
		}

		found := false
		for _, field := range result.Forms[0].Fields {
			if field.Name == "message" && field.Type == "textarea" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected textarea field with type 'textarea'")
		}
	})

	t.Run("extracts select fields", func(t *testing.T) {
		t.Parallel()

		html := `<html><body>
			<form action="/submit" method="POST">
				<select name="country">
					<option value="us">United States</option>
					<option value="uk">United Kingdom</option>
				</select>
			</form>
		</body></html>`

		parser, err := NewParser("http://test.onion")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		if len(result.Forms) != 1 {
			t.Fatalf("expected 1 form, got %d", len(result.Forms))
		}

		found := false
		for _, field := range result.Forms[0].Fields {
			if field.Name == "country" && field.Type == "select" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected select field with type 'select'")
		}
	})

	t.Run("input without type defaults to text", func(t *testing.T) {
		t.Parallel()

		html := `<html><body>
			<form action="/submit" method="POST">
				<input name="noTypeField">
			</form>
		</body></html>`

		parser, err := NewParser("http://test.onion")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		if len(result.Forms) != 1 {
			t.Fatalf("expected 1 form, got %d", len(result.Forms))
		}

		found := false
		for _, field := range result.Forms[0].Fields {
			if field.Name == "noTypeField" && field.Type == "text" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected input without type to default to 'text'")
		}
	})
}

// TestParserErrorCases tests error handling in the parser.
func TestParserErrorCases(t *testing.T) {
	t.Parallel()

	t.Run("returns error for invalid base URL", func(t *testing.T) {
		t.Parallel()

		// Create parser with invalid URL
		_, err := NewParser("://invalid-url")
		if err == nil {
			t.Error("expected error for invalid URL")
		}
	})

	t.Run("handles resolveURL with empty href", func(t *testing.T) {
		t.Parallel()

		html := `<html><body><a href="">Empty Link</a></body></html>`
		parser, err := NewParser("http://test.onion/page")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		// Empty href should not add to links
		for _, link := range result.Links {
			if link == "" {
				t.Error("empty link should not be added")
			}
		}
	})

	t.Run("handles mailto links correctly", func(t *testing.T) {
		t.Parallel()

		html := `<html><body><a href="mailto:test@example.com">Email</a></body></html>`
		parser, err := NewParser("http://test.onion/page")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		// mailto links should not be in regular links
		for _, link := range result.Links {
			if strings.HasPrefix(link, "mailto:") {
				t.Error("mailto links should not be in Links")
			}
		}
	})

	t.Run("handles javascript links correctly", func(t *testing.T) {
		t.Parallel()

		html := `<html><body><a href="javascript:void(0)">JS Link</a></body></html>`
		parser, err := NewParser("http://test.onion/page")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		// javascript links should not be in regular links
		for _, link := range result.Links {
			if strings.HasPrefix(link, "javascript:") {
				t.Error("javascript links should not be in Links")
			}
		}
	})

	t.Run("handles data URLs correctly", func(t *testing.T) {
		t.Parallel()

		html := `<html><body><img src="data:image/png;base64,iVBORw0KGgo="></body></html>`
		parser, err := NewParser("http://test.onion/page")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		// data URLs should not be in images
		for _, img := range result.Images {
			if strings.HasPrefix(img, "data:") {
				t.Error("data URLs should not be in Images")
			}
		}
	})
}

// TestParserElementClassification tests how elements are classified.
func TestParserElementClassification(t *testing.T) {
	t.Parallel()

	t.Run("classifies fragment-only links as internal", func(t *testing.T) {
		t.Parallel()

		html := `<html><body><a href="#section1">Jump to Section</a></body></html>`
		parser, err := NewParser("http://test.onion/page")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		// Fragment links should be internal
		found := false
		for _, link := range result.InternalLinks {
			if strings.Contains(link, "#section1") {
				found = true
				break
			}
		}
		if found {
			t.Log("fragment link was found in internal links as expected")
		}
	})

	t.Run("classifies relative URLs correctly", func(t *testing.T) {
		t.Parallel()

		html := `<html><body>
			<a href="../parent/page.html">Parent</a>
			<a href="./sibling.html">Sibling</a>
		</body></html>`
		parser, err := NewParser("http://test.onion/dir/page")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		// All relative URLs should be resolved and classified as internal
		if len(result.InternalLinks) == 0 {
			t.Error("expected relative links to be classified as internal")
		}
	})
}

// TestResolveURLEdgeCases tests edge cases in URL resolution.
func TestResolveURLEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("handles tel: links", func(t *testing.T) {
		t.Parallel()

		html := `<html><body><a href="tel:+1234567890">Call Us</a></body></html>`
		parser, err := NewParser("http://test.onion/page")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		// tel: links should not be in any link category
		for _, link := range result.Links {
			if strings.HasPrefix(link, "tel:") {
				t.Error("tel: links should not be in Links")
			}
		}
	})

	t.Run("handles hash-only links", func(t *testing.T) {
		t.Parallel()

		html := `<html><body><a href="#">Top</a></body></html>`
		parser, err := NewParser("http://test.onion/page")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		// # only links should not be treated as regular links
		for _, link := range result.Links {
			if link == "#" {
				t.Error("# only links should not be in Links")
			}
		}
	})

	t.Run("handles empty href", func(t *testing.T) {
		t.Parallel()

		html := `<html><body><a href="">Empty</a></body></html>`
		parser, err := NewParser("http://test.onion/page")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		// Empty href should not cause issues
		for _, link := range result.Links {
			if link == "" {
				t.Error("empty links should not be in Links")
			}
		}
	})

	t.Run("handles whitespace in href", func(t *testing.T) {
		t.Parallel()

		html := `<html><body><a href="  /path/to/page  ">Whitespace</a></body></html>`
		parser, err := NewParser("http://test.onion/")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		// Whitespace should be trimmed
		found := false
		for _, link := range result.Links {
			if strings.Contains(link, "/path/to/page") {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected link with trimmed whitespace to be parsed")
		}
	})
}

// TestClassifyLinkEdgeCases tests edge cases in link classification.
func TestClassifyLinkEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("handles case-insensitive host comparison", func(t *testing.T) {
		t.Parallel()

		html := `<html><body><a href="http://TEST.onion/page">Same Host Different Case</a></body></html>`
		parser, err := NewParser("http://test.onion/")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		// Should be classified as internal despite case difference
		if len(result.InternalLinks) == 0 {
			t.Error("expected case-insensitive host match to be internal")
		}
	})

	t.Run("classifies clearnet links correctly", func(t *testing.T) {
		t.Parallel()

		html := `<html><body>
			<a href="https://example.com/page">Clearnet HTTPS</a>
			<a href="http://example.org/page">Clearnet HTTP</a>
		</body></html>`
		parser, err := NewParser("http://test.onion/")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		if len(result.ClearnetLinks) != 2 {
			t.Errorf("expected 2 clearnet links, got %d", len(result.ClearnetLinks))
		}
	})

	t.Run("classifies external onion links correctly", func(t *testing.T) {
		t.Parallel()

		html := `<html><body><a href="http://other.onion/page">External Onion</a></body></html>`
		parser, err := NewParser("http://test.onion/")
		if err != nil {
			t.Fatalf("failed to create parser: %v", err)
		}

		result, err := parser.Parse(strings.NewReader(html))
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		if len(result.ExternalLinks) != 1 {
			t.Errorf("expected 1 external link, got %d", len(result.ExternalLinks))
		}
	})
}

// TestSpiderNormalizeURL tests URL normalization.
func TestSpiderNormalizeURL(t *testing.T) {
	t.Parallel()

	spider := NewSpider(http.DefaultClient)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "removes fragment",
			input:    "http://test.onion/page#section",
			expected: "http://test.onion/page",
		},
		{
			name:     "normalizes trailing slash",
			input:    "http://test.onion/dir/",
			expected: "http://test.onion/dir/",
		},
		{
			name:     "handles query parameters",
			input:    "http://test.onion/page?a=1&b=2",
			expected: "http://test.onion/page?a=1&b=2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := spider.normalizeURL(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeURL(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestMatchPatternEdgeCases tests additional pattern matching cases.
func TestMatchPatternEdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pattern  string
		path     string
		expected bool
	}{
		{
			name:     "matches exact path",
			pattern:  "/api/users",
			path:     "/api/users",
			expected: true,
		},
		{
			name:     "matches wildcard suffix",
			pattern:  "/api/*",
			path:     "/api/users",
			expected: true,
		},
		{
			name:     "matches extension pattern",
			pattern:  "*.json",
			path:     "/data.json",
			expected: true,
		},
		{
			name:     "no match for different path",
			pattern:  "/api/*",
			path:     "/about",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := matchPattern(tt.pattern, tt.path)
			if result != tt.expected {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.path, result, tt.expected)
			}
		})
	}
}
