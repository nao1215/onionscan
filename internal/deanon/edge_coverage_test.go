package deanon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nao1215/onionscan/internal/model"
)

func TestSocialAnalyzerEdgePaths(t *testing.T) {
	t.Parallel()

	analyzer := NewSocialAnalyzer()
	if !analyzer.isCommonWord("ADMIN") || analyzer.isCommonWord("onionoperator") {
		t.Fatal("common-word classification failed")
	}
	longURL := "https://social.example/" + strings.Repeat("x", 100)
	if sanitized := analyzer.sanitizeValue(longURL, ""); len(sanitized) != 103 || !strings.HasSuffix(sanitized, "...") {
		t.Fatalf("unexpected sanitized URL: %q", sanitized)
	}
	if title := analyzer.titleForPlatform("custom network"); title != "Custom Network" {
		t.Fatalf("fallback title = %q", title)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	findings, err := analyzer.Analyze(ctx, &AnalysisData{Pages: []*model.Page{{}}})
	if !errors.Is(err, context.Canceled) || len(findings) != 0 {
		t.Fatalf("cancelled Analyze() findings=%v err=%v", findings, err)
	}
}

func TestPrivateKeyAnalyzerRawAndSanitizationPaths(t *testing.T) {
	t.Parallel()

	analyzer := NewPrivateKeyAnalyzer()
	data := &AnalysisData{Pages: []*model.Page{{
		URL:      "http://test.onion/config",
		Snapshot: "public configuration",
		Raw:      []byte("token=ghp_1234567890abcdefghijklmnopqrstuvwxyz"),
	}}}
	findings, err := analyzer.Analyze(context.Background(), data)
	if err != nil || len(findings) == 0 {
		t.Fatalf("raw Analyze() findings=%v err=%v", findings, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := analyzer.Analyze(ctx, data); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}

	tests := []struct {
		value   string
		keyType string
		want    string
	}{
		{"-----BEGIN RSA PRIVATE KEY-----\nsecret", "rsa_private_key", "-----BEGIN RSA PRIVATE KEY-----..."},
		{"AKIAIOSFODNN7EXAMPLE", "aws_access_key", "AKIAIOSFOD...[REDACTED]"},
		{"short", "aws_access_key", "short"},
		{strings.Repeat("x", 21), "api_key", strings.Repeat("x", 20) + "...[REDACTED]"},
		{"short", "api_key", "short"},
	}
	for _, tc := range tests {
		if got := analyzer.sanitizeKeyValue(tc.value, tc.keyType); got != tc.want {
			t.Errorf("sanitizeKeyValue(%q, %q) = %q, want %q", tc.value, tc.keyType, got, tc.want)
		}
	}
	if title := analyzer.titleForPattern("unknown"); title != "Private Key Material Exposed" {
		t.Fatalf("fallback title = %q", title)
	}
}

func TestCloudAnalyzerEdgePaths(t *testing.T) {
	t.Parallel()

	analyzer := NewCloudAnalyzer()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := analyzer.Analyze(ctx, &AnalysisData{Pages: []*model.Page{{}}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}

	findings := analyzer.checkHeaders(map[string][]string{
		"X-Azure-Ref":  {"azure"},
		"X-Goog-Test":  {"gcp"},
		"Server":       {"cloudflare awselb"},
		"Cf-Ray-Empty": {},
	}, "http://test.onion/")
	if len(findings) < 5 {
		t.Fatalf("expected cloud header findings, got %d", len(findings))
	}
	if got := analyzer.truncateValue(strings.Repeat("x", 51)); !strings.HasSuffix(got, "...") {
		t.Fatalf("long value was not truncated: %q", got)
	}
	if title := analyzer.titleForPattern("unknown"); title != "Cloud Service Detected" {
		t.Fatalf("fallback title = %q", title)
	}
}

func TestHeaderAnalyzerEdgePaths(t *testing.T) {
	t.Parallel()

	analyzer := NewHeaderAnalyzer()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := analyzer.Analyze(ctx, &AnalysisData{Pages: []*model.Page{{}}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}

	page := &model.Page{
		URL: "http://test.onion/",
		Headers: map[string][]string{
			"ETag":                      {strings.Repeat("e", 21)},
			"Content-Security-Policy":   {"default-src https://example.com 'unsafe-eval'"},
			"Set-Cookie":                {"session=secret; Max-Age=86400"},
			"Strict-Transport-Security": {"max-age=31536000; preload"},
		},
	}
	findings, err := analyzer.Analyze(context.Background(), &AnalysisData{Pages: []*model.Page{page, page}})
	if err != nil || len(findings) < 7 {
		t.Fatalf("Analyze() findings=%d err=%v", len(findings), err)
	}
}
