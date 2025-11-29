package deanon

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/nao1215/onionscan/internal/model"
)

// ErrNoPDFHTTPClient is returned when no HTTP client is configured.
var ErrNoPDFHTTPClient = errors.New("no HTTP client configured: must use SetHTTPClient with Tor-proxied client")

// PDFAnalyzer extracts metadata from PDF files that could reveal
// identity or correlation information.
//
// IMPORTANT: This analyzer requires a Tor-proxied HTTP client to be set
// via SetHTTPClient before use. It will refuse to fetch PDFs without
// a properly configured client to prevent IP leakage.
//
// PDF metadata often contains:
//   - Author name (from OS user account or software settings)
//   - Creator application (reveals software used)
//   - Producer (PDF generation library)
//   - Creation and modification dates
//   - Title and subject
//   - Custom metadata fields
type PDFAnalyzer struct {
	// httpClient for downloading PDFs (MUST be Tor-proxied)
	httpClient *http.Client

	// maxPDFSize limits download size (default 10MB)
	maxPDFSize int64

	// pdfURLPattern matches PDF file URLs
	pdfURLPattern *regexp.Regexp

	// targetHost is the .onion host being scanned (for same-origin restriction)
	targetHost string

	// allowExternalFetch enables fetching from non-target hosts (dangerous, opt-in only)
	allowExternalFetch bool
}

// NewPDFAnalyzer creates a new PDFAnalyzer.
// NOTE: You MUST call SetHTTPClient with a Tor-proxied client before use.
func NewPDFAnalyzer() *PDFAnalyzer {
	return &PDFAnalyzer{
		httpClient:    nil,              // Must be explicitly set with Tor-proxied client
		maxPDFSize:    10 * 1024 * 1024, // 10MB
		pdfURLPattern: regexp.MustCompile(`(?i)\.pdf(?:\?.*)?$`),
	}
}

// Name returns the analyzer name.
func (a *PDFAnalyzer) Name() string {
	return "pdf"
}

// Category returns the analyzer category.
func (a *PDFAnalyzer) Category() string {
	return CategoryIdentity
}

// Analyze searches for PDF files and extracts their metadata.
func (a *PDFAnalyzer) Analyze(ctx context.Context, data *AnalysisData) ([]model.Finding, error) {
	// Fail closed: refuse to run without a Tor-proxied client
	if a.httpClient == nil {
		return nil, ErrNoPDFHTTPClient
	}

	findings := make([]model.Finding, 0)
	processedURLs := make(map[string]bool)

	// Set target host for same-origin restriction
	a.targetHost = data.HiddenService

	for _, page := range data.Pages {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Find PDF URLs in the page
		pdfURLs := a.extractPDFURLs(page)

		for _, pdfURL := range pdfURLs {
			if processedURLs[pdfURL] {
				continue
			}
			processedURLs[pdfURL] = true

			// Extract metadata from PDF
			pdfFindings := a.analyzePDF(ctx, pdfURL, page.URL)
			findings = append(findings, pdfFindings...)
		}
	}

	return findings, nil
}

// extractPDFURLs finds PDF URLs from the page.
func (a *PDFAnalyzer) extractPDFURLs(page *model.Page) []string {
	urls := make(map[string]bool)

	// Check page URL itself
	if a.pdfURLPattern.MatchString(page.URL) {
		urls[page.URL] = true
	}

	// Check links
	for _, link := range page.Links {
		if a.pdfURLPattern.MatchString(link.Source) {
			urls[link.Source] = true
		}
	}

	// Search for PDF links in content
	linkPattern := regexp.MustCompile(`(?i)href\s*=\s*["']([^"']*\.pdf(?:\?[^"']*)?)["']`)
	matches := linkPattern.FindAllStringSubmatch(page.Snapshot, -1)
	for _, m := range matches {
		if len(m) > 1 {
			urls[m[1]] = true
		}
	}

	result := make([]string, 0, len(urls))
	for u := range urls {
		result = append(result, u)
	}
	return result
}

// isAllowedURL checks if fetching the URL is allowed based on same-origin policy.
// Only .onion URLs from the target host are allowed by default.
func (a *PDFAnalyzer) isAllowedURL(pdfURL string) bool {
	parsed, err := url.Parse(pdfURL)
	if err != nil {
		return false
	}

	host := parsed.Hostname()

	// Always allow same-origin requests to target .onion
	if host == a.targetHost {
		return true
	}

	// Check if it's a .onion URL (other onion services)
	if strings.HasSuffix(host, ".onion") {
		// Allow other .onion URLs only if external fetch is enabled
		return a.allowExternalFetch
	}

	// Clearnet URLs are never allowed (would leak IP)
	return false
}

// analyzePDF downloads and analyzes a PDF file.
func (a *PDFAnalyzer) analyzePDF(ctx context.Context, pdfURL, _ string) []model.Finding {
	findings := make([]model.Finding, 0)

	// Security check: only fetch from allowed URLs
	if !a.isAllowedURL(pdfURL) {
		// Skip silently - don't fetch from external/clearnet sources
		return findings
	}

	// Download PDF
	pdfData, err := a.downloadPDF(ctx, pdfURL)
	if err != nil || pdfData == nil {
		// Cannot download PDF, skip
		return findings
	}

	// Extract metadata from PDF content
	metadata := a.extractPDFMetadata(pdfData)

	// Generate findings from metadata
	for key, value := range metadata {
		if value == "" {
			continue
		}

		finding := a.createFindingFromMetadata(key, value, pdfURL)
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings
}

// downloadPDF downloads a PDF file with size limits.
func (a *PDFAnalyzer) downloadPDF(ctx context.Context, pdfURL string) ([]byte, error) {
	// Fail closed: refuse to fetch without Tor-proxied client
	if a.httpClient == nil {
		return nil, ErrNoPDFHTTPClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pdfURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check content type
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "pdf") && !strings.Contains(contentType, "octet-stream") {
		return nil, nil
	}

	// Read with size limit
	limitReader := io.LimitReader(resp.Body, a.maxPDFSize)
	return io.ReadAll(limitReader)
}

// extractPDFMetadata extracts metadata from PDF content.
// This is a simplified implementation that parses PDF trailer/info dictionary.
func (a *PDFAnalyzer) extractPDFMetadata(data []byte) map[string]string {
	metadata := make(map[string]string)
	content := string(data)

	// Look for Info dictionary fields in PDF
	// PDF metadata is typically in /Info dictionary or XMP metadata

	// Standard PDF Info dictionary fields
	patterns := map[string]*regexp.Regexp{
		"author":       regexp.MustCompile(`/Author\s*\(([^)]+)\)|/Author\s*<([^>]+)>`),
		"creator":      regexp.MustCompile(`/Creator\s*\(([^)]+)\)|/Creator\s*<([^>]+)>`),
		"producer":     regexp.MustCompile(`/Producer\s*\(([^)]+)\)|/Producer\s*<([^>]+)>`),
		"title":        regexp.MustCompile(`/Title\s*\(([^)]+)\)|/Title\s*<([^>]+)>`),
		"subject":      regexp.MustCompile(`/Subject\s*\(([^)]+)\)|/Subject\s*<([^>]+)>`),
		"keywords":     regexp.MustCompile(`/Keywords\s*\(([^)]+)\)|/Keywords\s*<([^>]+)>`),
		"creationDate": regexp.MustCompile(`/CreationDate\s*\(([^)]+)\)|/CreationDate\s*<([^>]+)>`),
		"modDate":      regexp.MustCompile(`/ModDate\s*\(([^)]+)\)|/ModDate\s*<([^>]+)>`),
	}

	for field, pattern := range patterns {
		if matches := pattern.FindStringSubmatch(content); len(matches) > 1 {
			// Get first non-empty match
			for _, m := range matches[1:] {
				if m != "" {
					metadata[field] = a.decodePDFString(m)
					break
				}
			}
		}
	}

	// Look for XMP metadata (more detailed)
	xmpPatterns := map[string]*regexp.Regexp{
		"xmp_creator":       regexp.MustCompile(`<dc:creator[^>]*>.*?<rdf:li[^>]*>([^<]+)</rdf:li>`),
		"xmp_tool":          regexp.MustCompile(`xmp:CreatorTool>([^<]+)<`),
		"xmp_producer":      regexp.MustCompile(`pdf:Producer>([^<]+)<`),
		"xmp_documentId":    regexp.MustCompile(`xmpMM:DocumentID>([^<]+)<`),
		"xmp_instanceId":    regexp.MustCompile(`xmpMM:InstanceID>([^<]+)<`),
		"xmp_originalDocId": regexp.MustCompile(`xmpMM:OriginalDocumentID>([^<]+)<`),
	}

	for field, pattern := range xmpPatterns {
		if matches := pattern.FindStringSubmatch(content); len(matches) > 1 {
			metadata[field] = matches[1]
		}
	}

	return metadata
}

// decodePDFString decodes PDF string encoding.
func (a *PDFAnalyzer) decodePDFString(s string) string {
	// Handle hex strings (common in PDFs)
	if strings.HasPrefix(s, "FEFF") || strings.HasPrefix(s, "feff") {
		// UTF-16BE BOM, convert hex to string
		return a.decodeHexString(s)
	}

	// Handle escaped characters
	s = strings.ReplaceAll(s, "\\n", "\n")
	s = strings.ReplaceAll(s, "\\r", "\r")
	s = strings.ReplaceAll(s, "\\t", "\t")
	s = strings.ReplaceAll(s, "\\(", "(")
	s = strings.ReplaceAll(s, "\\)", ")")
	s = strings.ReplaceAll(s, "\\\\", "\\")

	return strings.TrimSpace(s)
}

// decodeHexString decodes a hex-encoded PDF string.
func (a *PDFAnalyzer) decodeHexString(hex string) string {
	// Skip BOM and convert pairs of hex digits
	if len(hex) < 4 {
		return hex
	}

	// Simple hex decode (skip BOM)
	hex = hex[4:] // Skip FEFF BOM
	var result []byte
	for i := 0; i+3 < len(hex); i += 4 {
		// UTF-16BE: 2 bytes per character
		var char rune
		for j := range 4 {
			char <<= 4
			c := hex[i+j]
			switch {
			case c >= '0' && c <= '9':
				char |= rune(c - '0')
			case c >= 'a' && c <= 'f':
				char |= rune(c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				char |= rune(c - 'A' + 10)
			}
		}
		if char > 0 {
			result = append(result, byte(char))
		}
	}

	return string(result)
}

// createFindingFromMetadata creates a finding from metadata field.
func (a *PDFAnalyzer) createFindingFromMetadata(field, value, location string) *model.Finding {
	// Skip empty or generic values
	if value == "" || len(value) < 3 {
		return nil
	}

	switch field {
	case "author":
		// Author field often contains real names
		return &model.Finding{
			Type:         "pdf_author",
			Title:        "PDF Author Metadata",
			Description:  "The PDF contains author metadata that may reveal identity.",
			Severity:     model.SeverityHigh,
			SeverityText: model.SeverityHigh.String(),
			Value:        value,
			Location:     location,
		}

	case "creator", "xmp_tool":
		// Creator reveals software used
		return &model.Finding{
			Type:         "pdf_creator",
			Title:        "PDF Creator Software",
			Description:  "The PDF was created with specific software, which may help identify the source.",
			Severity:     model.SeverityMedium,
			SeverityText: model.SeverityMedium.String(),
			Value:        value,
			Location:     location,
		}

	case "producer", "xmp_producer":
		// Producer reveals PDF library/converter
		return &model.Finding{
			Type:         "pdf_producer",
			Title:        "PDF Producer Library",
			Description:  "The PDF generation library is revealed.",
			Severity:     model.SeverityLow,
			SeverityText: model.SeverityLow.String(),
			Value:        value,
			Location:     location,
		}

	case "xmp_documentId", "xmp_instanceId", "xmp_originalDocId":
		// Document IDs can be used for correlation
		return &model.Finding{
			Type:         "pdf_document_id",
			Title:        "PDF Document Identifier",
			Description:  "The PDF contains a unique document ID that could be used for correlation.",
			Severity:     model.SeverityMedium,
			SeverityText: model.SeverityMedium.String(),
			Value:        value,
			Location:     location,
		}

	case "xmp_creator":
		// XMP creator often has more detailed info
		return &model.Finding{
			Type:         "pdf_xmp_creator",
			Title:        "PDF XMP Creator Metadata",
			Description:  "XMP metadata contains creator information.",
			Severity:     model.SeverityHigh,
			SeverityText: model.SeverityHigh.String(),
			Value:        value,
			Location:     location,
		}

	case "creationDate", "modDate":
		// Dates can reveal timezone info
		if strings.Contains(value, "+") || strings.Contains(value, "-") {
			return &model.Finding{
				Type:         "pdf_timezone",
				Title:        "PDF Timezone Information",
				Description:  "PDF date metadata contains timezone information.",
				Severity:     model.SeverityMedium,
				SeverityText: model.SeverityMedium.String(),
				Value:        value,
				Location:     location,
			}
		}
	}

	return nil
}

// SetHTTPClient sets a Tor-proxied HTTP client.
// This MUST be called before Analyze() with a properly configured Tor proxy client.
func (a *PDFAnalyzer) SetHTTPClient(client *http.Client) {
	a.httpClient = client
}

// SetAllowExternalFetch enables fetching from non-target .onion hosts.
// WARNING: This is dangerous and should only be used when explicitly requested.
// Clearnet URLs are NEVER fetched regardless of this setting.
func (a *PDFAnalyzer) SetAllowExternalFetch(allow bool) {
	a.allowExternalFetch = allow
}

// Ensure PDFAnalyzer implements CheckAnalyzer.
var _ CheckAnalyzer = (*PDFAnalyzer)(nil)
