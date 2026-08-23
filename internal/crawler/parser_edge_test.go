package crawler

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

type parserFailingReader struct{}

func (parserFailingReader) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

func TestParserEdgePaths(t *testing.T) {
	t.Parallel()

	parser, err := NewParser("http://test.onion/base")
	if err != nil {
		t.Fatalf("create parser: %v", err)
	}
	if _, err := parser.Parse(parserFailingReader{}); err == nil {
		t.Fatal("expected reader error")
	}

	result, err := parser.Parse(strings.NewReader(`
		<html><head><title></title>
		<link rel="icon" href="/favicon.ico">
		<link rel="shortcut icon" href="/legacy.ico"></head>
		<body><form><input name="query"></form></body></html>`))
	if err != nil {
		t.Fatalf("parse edge document: %v", err)
	}
	if len(result.Forms) != 1 || result.Forms[0].Method != http.MethodGet || len(result.Images) != 2 {
		t.Fatalf("unexpected parse result: %+v", result)
	}

	for _, href := range []string{"tel:+123", "#", "http://%"} {
		if resolved := parser.resolveURL(href); resolved != "" {
			t.Errorf("resolveURL(%q) = %q, want empty", href, resolved)
		}
	}
	classified := &ParseResult{}
	parser.classifyLink("http://%", classified)
	parser.classifyLink("relative", classified)
	if len(classified.InternalLinks) != 1 || classified.InternalLinks[0] != "relative" {
		t.Fatalf("relative link was not classified as internal: %+v", classified)
	}
}
