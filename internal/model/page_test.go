package model

import (
	"strings"
	"testing"
)

// TestPageComputeHash tests the ComputeHash method.
func TestPageComputeHash(t *testing.T) {
	t.Parallel()

	t.Run("computes SHA256 hash of raw content", func(t *testing.T) {
		t.Parallel()

		page := &Page{
			Raw: []byte("Hello, World!"),
		}
		page.ComputeHash()

		// Expected SHA256 of "Hello, World!"
		expected := "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
		if page.Hash != expected {
			t.Errorf("got %q, expected %q", page.Hash, expected)
		}
	})

	t.Run("empty content produces empty hash", func(t *testing.T) {
		t.Parallel()

		page := &Page{
			Raw: []byte{},
		}
		page.ComputeHash()

		if page.Hash != "" {
			t.Errorf("expected empty hash, got %q", page.Hash)
		}
	})

	t.Run("nil content produces empty hash", func(t *testing.T) {
		t.Parallel()

		page := &Page{
			Raw: nil,
		}
		page.ComputeHash()

		if page.Hash != "" {
			t.Errorf("expected empty hash, got %q", page.Hash)
		}
	})
}

// TestPageGetHeader tests the GetHeader method.
func TestPageGetHeader(t *testing.T) {
	t.Parallel()

	t.Run("returns first header value", func(t *testing.T) {
		t.Parallel()

		page := &Page{
			Headers: map[string][]string{
				"Content-Type": {"text/html; charset=utf-8"},
				"Set-Cookie":   {"session=abc123", "theme=dark"},
			},
		}

		if got := page.GetHeader("Content-Type"); got != "text/html; charset=utf-8" {
			t.Errorf("got %q, expected 'text/html; charset=utf-8'", got)
		}
	})

	t.Run("returns empty string for missing header", func(t *testing.T) {
		t.Parallel()

		page := &Page{
			Headers: map[string][]string{},
		}

		if got := page.GetHeader("X-Missing"); got != "" {
			t.Errorf("got %q, expected empty string", got)
		}
	})

	t.Run("returns empty string for empty header list", func(t *testing.T) {
		t.Parallel()

		page := &Page{
			Headers: map[string][]string{
				"Empty": {},
			},
		}

		if got := page.GetHeader("Empty"); got != "" {
			t.Errorf("got %q, expected empty string", got)
		}
	})
}

// TestPageGetAllHeaders tests the GetAllHeaders method.
func TestPageGetAllHeaders(t *testing.T) {
	t.Parallel()

	t.Run("returns all header values", func(t *testing.T) {
		t.Parallel()

		page := &Page{
			Headers: map[string][]string{
				"Set-Cookie": {"session=abc123", "theme=dark"},
			},
		}

		values := page.GetAllHeaders("Set-Cookie")
		if len(values) != 2 {
			t.Errorf("got %d values, expected 2", len(values))
		}
	})

	t.Run("returns nil for missing header", func(t *testing.T) {
		t.Parallel()

		page := &Page{
			Headers: map[string][]string{},
		}

		if values := page.GetAllHeaders("X-Missing"); values != nil {
			t.Errorf("expected nil, got %v", values)
		}
	})
}

// TestPageIsHTML tests the IsHTML method.
func TestPageIsHTML(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		contentType string
		expected    bool
	}{
		{"text/html", true},
		{"text/html; charset=utf-8", true},
		{"application/xhtml+xml", true},
		{"application/json", false},
		{"text/plain", false},
		{"image/png", false},
		{"", false},
	}

	for _, tc := range testCases {
		t.Run(tc.contentType, func(t *testing.T) {
			t.Parallel()

			page := &Page{ContentType: tc.contentType}
			if page.IsHTML() != tc.expected {
				t.Errorf("IsHTML() for %q = %v, expected %v", tc.contentType, page.IsHTML(), tc.expected)
			}
		})
	}
}

// TestPageIsImage tests the IsImage method.
func TestPageIsImage(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		contentType string
		expected    bool
	}{
		{"image/png", true},
		{"image/jpeg", true},
		{"image/gif", true},
		{"image/webp", true},
		{"text/html", false},
		{"application/json", false},
		{"", false},
	}

	for _, tc := range testCases {
		t.Run(tc.contentType, func(t *testing.T) {
			t.Parallel()

			page := &Page{ContentType: tc.contentType}
			if page.IsImage() != tc.expected {
				t.Errorf("IsImage() for %q = %v, expected %v", tc.contentType, page.IsImage(), tc.expected)
			}
		})
	}
}

// TestPageTruncateSnapshot tests the TruncateSnapshot method.
func TestPageTruncateSnapshot(t *testing.T) {
	t.Parallel()

	t.Run("does not truncate small snapshot", func(t *testing.T) {
		t.Parallel()

		content := "Small content"
		page := &Page{Snapshot: content}
		page.TruncateSnapshot()

		if page.Snapshot != content {
			t.Errorf("snapshot was modified")
		}
	})

	t.Run("truncates large snapshot to MaxSnapshotSize", func(t *testing.T) {
		t.Parallel()

		// Create content larger than MaxSnapshotSize
		content := strings.Repeat("a", MaxSnapshotSize+1000)
		page := &Page{Snapshot: content}
		page.TruncateSnapshot()

		if len(page.Snapshot) != MaxSnapshotSize {
			t.Errorf("got length %d, expected %d", len(page.Snapshot), MaxSnapshotSize)
		}
	})
}

// TestPageTruncateRaw tests the TruncateRaw method.
func TestPageTruncateRaw(t *testing.T) {
	t.Parallel()

	t.Run("does not truncate small content", func(t *testing.T) {
		t.Parallel()

		content := []byte("Small content")
		page := &Page{Raw: content}
		page.TruncateRaw()

		if len(page.Raw) != len(content) {
			t.Errorf("raw content was modified")
		}
	})

	t.Run("truncates large content to MaxPageSize", func(t *testing.T) {
		t.Parallel()

		// Create content larger than MaxPageSize
		content := make([]byte, MaxPageSize+1000)
		page := &Page{Raw: content}
		page.TruncateRaw()

		if len(page.Raw) != MaxPageSize {
			t.Errorf("got length %d, expected %d", len(page.Raw), MaxPageSize)
		}
	})
}
