package model

import (
	"crypto/sha256"
	"encoding/hex"
)

// Page represents a crawled web page with all extracted information.
// This structure holds both the raw response data and parsed content.
//
// Design decision: We store both raw bytes and parsed content because:
// 1. Raw bytes are needed for binary analysis (EXIF, etc.)
// 2. Parsed content is needed for deanonymization checks
// 3. The hash allows deduplication and change detection
type Page struct {
	// URL is the full URL of the page including the .onion address.
	URL string `json:"url"`

	// StatusCode is the HTTP response status code.
	StatusCode int `json:"status_code"`

	// Headers contains all HTTP response headers.
	// Keys are header names (canonicalized), values are slices of header values.
	Headers map[string][]string `json:"headers"`

	// ContentType is the MIME type of the response.
	// Extracted from Content-Type header for convenience.
	ContentType string `json:"content_type"`

	// Title is the page title extracted from <title> tag.
	// Empty for non-HTML content.
	Title string `json:"title,omitempty"`

	// Forms contains all HTML forms found on the page.
	// Useful for detecting login pages, search forms, etc.
	Forms []Form `json:"forms,omitempty"`

	// Images contains all images referenced by the page.
	// Includes <img> tags and CSS background images.
	Images []Element `json:"images,omitempty"`

	// Anchors contains all anchor (<a>) elements.
	// Used for crawling and link analysis.
	Anchors []Element `json:"anchors,omitempty"`

	// Links contains <link> elements (stylesheets, icons, etc.).
	Links []Element `json:"links,omitempty"`

	// Scripts contains all script references and inline scripts.
	Scripts []Element `json:"scripts,omitempty"`

	// Styles contains all CSS references.
	Styles []Element `json:"styles,omitempty"`

	// Snapshot is a text-only snapshot of the page content.
	// Limited to MaxSnapshotSize bytes to prevent memory issues.
	// Useful for text-based deanonymization checks.
	Snapshot string `json:"snapshot,omitempty"`

	// Raw contains the raw response body bytes.
	// Limited to MaxPageSize bytes.
	// Used for binary analysis (EXIF extraction, etc.).
	Raw []byte `json:"-"` // Excluded from JSON to reduce report size

	// Hash is the SHA-256 hash of the raw content.
	// Used for deduplication and change detection.
	Hash string `json:"hash"`

	// CSP contains the parsed Content-Security-Policy header.
	// Nil if no CSP header was present.
	CSP *CSPPolicy `json:"csp,omitempty"`

	// APIEndpoints contains detected API endpoints from JavaScript analysis.
	APIEndpoints []string `json:"api_endpoints,omitempty"`
}

// MaxSnapshotSize is the maximum size of the text snapshot in bytes.
// We limit this to prevent memory issues with very large pages.
const MaxSnapshotSize = 512 * 1024 // 512 KB

// MaxPageSize is the maximum size of raw page content to store.
// Larger pages are truncated to this size.
const MaxPageSize = 5 * 1024 * 1024 // 5 MB

// Form represents an HTML form element.
type Form struct {
	// Action is the form's action URL.
	// May be relative or absolute.
	Action string `json:"action"`

	// Method is the HTTP method (GET, POST, etc.).
	// Defaults to GET if not specified in HTML.
	Method string `json:"method"`

	// ID is the form's id attribute.
	ID string `json:"id,omitempty"`

	// Name is the form's name attribute.
	Name string `json:"name,omitempty"`

	// Inputs contains the form's input fields.
	Inputs []FormInput `json:"inputs,omitempty"`
}

// FormInput represents an input field in a form.
type FormInput struct {
	// Type is the input type (text, password, hidden, etc.).
	Type string `json:"type"`

	// Name is the input's name attribute.
	Name string `json:"name"`

	// ID is the input's id attribute.
	ID string `json:"id,omitempty"`

	// Value is the input's default value.
	Value string `json:"value,omitempty"`
}

// Element represents a generic HTML element with a source URL.
// Used for images, scripts, stylesheets, and anchors.
type Element struct {
	// Source is the element's src, href, or equivalent URL attribute.
	Source string `json:"source"`

	// Alt is the alt text (for images).
	Alt string `json:"alt,omitempty"`

	// Text is the inner text content (for anchors).
	Text string `json:"text,omitempty"`

	// Type is the element type or MIME type hint.
	Type string `json:"type,omitempty"`

	// Rel is the rel attribute (for links and anchors).
	Rel string `json:"rel,omitempty"`

	// Integrity is the integrity attribute (for subresource integrity).
	Integrity string `json:"integrity,omitempty"`

	// Crossorigin is the crossorigin attribute.
	Crossorigin string `json:"crossorigin,omitempty"`
}

// CSPPolicy represents a parsed Content-Security-Policy header.
// CSP is important for anonymity analysis because it can reveal
// external domains the site communicates with.
type CSPPolicy struct {
	// Raw is the original CSP header value.
	Raw string `json:"raw"`

	// DefaultSrc is the default-src directive values.
	DefaultSrc []string `json:"default_src,omitempty"`

	// ScriptSrc is the script-src directive values.
	ScriptSrc []string `json:"script_src,omitempty"`

	// StyleSrc is the style-src directive values.
	StyleSrc []string `json:"style_src,omitempty"`

	// ImgSrc is the img-src directive values.
	ImgSrc []string `json:"img_src,omitempty"`

	// ConnectSrc is the connect-src directive values.
	// Particularly important as it controls fetch/XHR/WebSocket destinations.
	ConnectSrc []string `json:"connect_src,omitempty"`

	// FontSrc is the font-src directive values.
	FontSrc []string `json:"font_src,omitempty"`

	// FrameSrc is the frame-src directive values.
	FrameSrc []string `json:"frame_src,omitempty"`

	// ReportURI is the report-uri directive value.
	// This is especially concerning for anonymity as it sends data to an external endpoint.
	ReportURI string `json:"report_uri,omitempty"`

	// ExternalDomains contains all unique external domains found in the policy.
	// This is computed during parsing for quick anonymity assessment.
	ExternalDomains []string `json:"external_domains,omitempty"`
}

// ComputeHash calculates and sets the SHA-256 hash of the page's raw content.
// This should be called after setting the Raw field.
func (p *Page) ComputeHash() {
	if len(p.Raw) == 0 {
		p.Hash = ""
		return
	}

	hash := sha256.Sum256(p.Raw)
	p.Hash = hex.EncodeToString(hash[:])
}

// GetHeader returns the first value of the specified header.
// Returns empty string if the header is not present.
// Header names are case-insensitive in HTTP, but Go's http package
// canonicalizes them, so we store them in canonical form.
func (p *Page) GetHeader(name string) string {
	if values, ok := p.Headers[name]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

// GetAllHeaders returns all values of the specified header.
// Returns nil if the header is not present.
func (p *Page) GetAllHeaders(name string) []string {
	return p.Headers[name]
}

// IsHTML returns true if the page content type indicates HTML.
func (p *Page) IsHTML() bool {
	return p.ContentType == "text/html" ||
		p.ContentType == "application/xhtml+xml" ||
		// Handle content types with charset suffix
		len(p.ContentType) > 9 && p.ContentType[:9] == "text/html"
}

// IsImage returns true if the page content type indicates an image.
func (p *Page) IsImage() bool {
	return len(p.ContentType) >= 6 && p.ContentType[:6] == "image/"
}

// TruncateSnapshot ensures the snapshot doesn't exceed MaxSnapshotSize.
// Call this after setting the snapshot to enforce the size limit.
func (p *Page) TruncateSnapshot() {
	if len(p.Snapshot) > MaxSnapshotSize {
		p.Snapshot = p.Snapshot[:MaxSnapshotSize]
	}
}

// TruncateRaw ensures the raw content doesn't exceed MaxPageSize.
// Call this after setting Raw to enforce the size limit.
func (p *Page) TruncateRaw() {
	if len(p.Raw) > MaxPageSize {
		p.Raw = p.Raw[:MaxPageSize]
	}
}
