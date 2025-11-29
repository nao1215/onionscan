package crawler

import (
	"io"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// HTML element name constants for form field detection.
const (
	htmlElementInput    = "input"
	htmlElementSelect   = "select"
	htmlElementTextarea = "textarea"
)

// Parser extracts information from HTML content.
// It identifies links, forms, metadata, and other interesting elements.
//
// Design decision: We use golang.org/x/net/html for parsing rather than
// regex because:
//  1. It correctly handles malformed HTML common on the web
//  2. Provides a proper DOM-like structure
//  3. More maintainable than complex regex patterns
//  4. Standard library extension, well-maintained
type Parser struct {
	// baseURL is the URL of the page being parsed, used for resolving relative URLs.
	baseURL *url.URL
}

// ParseResult contains all information extracted from an HTML page.
//
// Design decision: We return a comprehensive result struct rather than
// multiple methods because:
//  1. Single parsing pass is more efficient
//  2. Related data can be collected together
//  3. Caller can choose what to use
type ParseResult struct {
	// Title is the page title from <title> tag.
	Title string

	// Links contains all discovered URLs (href attributes).
	Links []string

	// InternalLinks are links within the same onion service.
	InternalLinks []string

	// ExternalLinks are links to different onion services or clearnet.
	ExternalLinks []string

	// ClearnetLinks are links to non-.onion domains.
	ClearnetLinks []string

	// Forms contains information about HTML forms.
	Forms []FormInfo

	// Scripts contains script sources.
	Scripts []string

	// Images contains image sources.
	Images []string

	// MetaTags contains meta tag information.
	MetaTags map[string]string

	// Emails contains extracted email addresses.
	Emails []string

	// OnionAddresses contains discovered .onion addresses.
	OnionAddresses []string

	// Comments contains HTML comments (may contain sensitive info).
	Comments []string
}

// FormInfo contains information about an HTML form.
type FormInfo struct {
	// Action is the form action URL.
	Action string

	// Method is the HTTP method (GET, POST).
	Method string

	// Fields contains form field names and types.
	Fields []FormField
}

// FormField represents a form input field.
type FormField struct {
	// Name is the field name attribute.
	Name string

	// Type is the input type (text, password, hidden, etc.).
	Type string

	// Value is the default value if present.
	Value string
}

// NewParser creates a new HTML parser with the given base URL.
// The base URL is used to resolve relative links.
func NewParser(baseURL string) (*Parser, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	return &Parser{baseURL: u}, nil
}

// Parse parses HTML content and extracts all relevant information.
func (p *Parser) Parse(content io.Reader) (*ParseResult, error) {
	doc, err := html.Parse(content)
	if err != nil {
		return nil, err
	}

	result := &ParseResult{
		Links:          make([]string, 0),
		InternalLinks:  make([]string, 0),
		ExternalLinks:  make([]string, 0),
		ClearnetLinks:  make([]string, 0),
		Forms:          make([]FormInfo, 0),
		Scripts:        make([]string, 0),
		Images:         make([]string, 0),
		MetaTags:       make(map[string]string),
		Emails:         make([]string, 0),
		OnionAddresses: make([]string, 0),
		Comments:       make([]string, 0),
	}

	// Collect text for email/onion extraction
	var textContent strings.Builder

	// Walk the DOM tree
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		switch n.Type {
		case html.ElementNode:
			p.processElement(n, result)
		case html.TextNode:
			textContent.WriteString(n.Data)
			textContent.WriteString(" ")
		case html.CommentNode:
			result.Comments = append(result.Comments, n.Data)
			// Comments might also contain interesting text
			textContent.WriteString(n.Data)
			textContent.WriteString(" ")
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}

	walk(doc)

	// Extract emails and onion addresses from all text
	text := textContent.String()
	result.Emails = p.extractEmails(text)
	result.OnionAddresses = p.extractOnionAddresses(text)

	return result, nil
}

// processElement handles HTML element nodes.
func (p *Parser) processElement(n *html.Node, result *ParseResult) {
	switch n.Data {
	case "title":
		// Extract title text
		if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
			result.Title = strings.TrimSpace(n.FirstChild.Data)
		}

	case "a":
		// Extract links
		if href := getAttr(n, "href"); href != "" {
			resolved := p.resolveURL(href)
			if resolved != "" {
				result.Links = append(result.Links, resolved)
				p.classifyLink(resolved, result)
			}
		}

	case "form":
		// Extract form information
		form := FormInfo{
			Action: p.resolveURL(getAttr(n, "action")),
			Method: strings.ToUpper(getAttr(n, "method")),
			Fields: make([]FormField, 0),
		}
		if form.Method == "" {
			form.Method = "GET"
		}
		// Extract form fields
		p.extractFormFields(n, &form)
		result.Forms = append(result.Forms, form)

	case "script":
		// Extract script sources
		if src := getAttr(n, "src"); src != "" {
			result.Scripts = append(result.Scripts, p.resolveURL(src))
		}

	case "img":
		// Extract image sources
		if src := getAttr(n, "src"); src != "" {
			result.Images = append(result.Images, p.resolveURL(src))
		}

	case "meta":
		// Extract meta tags
		name := getAttr(n, "name")
		if name == "" {
			name = getAttr(n, "property") // OpenGraph uses property
		}
		content := getAttr(n, "content")
		if name != "" && content != "" {
			result.MetaTags[name] = content
		}

	case "link":
		// Extract link elements (stylesheets, favicons, etc.)
		if href := getAttr(n, "href"); href != "" {
			rel := getAttr(n, "rel")
			if rel == "icon" || rel == "shortcut icon" {
				result.Images = append(result.Images, p.resolveURL(href))
			}
		}
	}
}

// extractFormFields recursively extracts form fields from a form element.
func (p *Parser) extractFormFields(n *html.Node, form *FormInfo) {
	if n.Type == html.ElementNode && (n.Data == htmlElementInput || n.Data == htmlElementSelect || n.Data == htmlElementTextarea) {
		field := FormField{
			Name:  getAttr(n, "name"),
			Type:  getAttr(n, "type"),
			Value: getAttr(n, "value"),
		}
		if field.Type == "" {
			switch n.Data {
			case htmlElementTextarea:
				field.Type = htmlElementTextarea
			case htmlElementSelect:
				field.Type = htmlElementSelect
			default:
				field.Type = "text"
			}
		}
		if field.Name != "" {
			form.Fields = append(form.Fields, field)
		}
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		p.extractFormFields(c, form)
	}
}

// resolveURL resolves a relative URL against the base URL.
//
// Design decision: We resolve URLs rather than storing them as-is because:
//  1. Makes deduplication easier
//  2. Allows proper link classification
//  3. Reduces ambiguity in results
func (p *Parser) resolveURL(href string) string {
	if href == "" {
		return ""
	}

	// Handle special cases
	href = strings.TrimSpace(href)
	if strings.HasPrefix(href, "javascript:") ||
		strings.HasPrefix(href, "mailto:") ||
		strings.HasPrefix(href, "tel:") ||
		strings.HasPrefix(href, "data:") ||
		href == "#" {
		return ""
	}

	// Parse and resolve
	u, err := url.Parse(href)
	if err != nil {
		return ""
	}

	resolved := p.baseURL.ResolveReference(u)
	return resolved.String()
}

// classifyLink categorizes a link as internal, external, or clearnet.
func (p *Parser) classifyLink(link string, result *ParseResult) {
	u, err := url.Parse(link)
	if err != nil {
		return
	}

	host := u.Hostname()
	baseHost := p.baseURL.Hostname()

	// First check if it's the same host (including port for non-standard ports)
	// This handles both onion addresses and clearnet addresses (for testing)
	if strings.EqualFold(u.Host, p.baseURL.Host) || strings.EqualFold(host, baseHost) {
		result.InternalLinks = append(result.InternalLinks, link)
		return
	}

	// Check if it's an onion address
	if strings.HasSuffix(host, ".onion") {
		// Different onion service
		result.ExternalLinks = append(result.ExternalLinks, link)
	} else if host != "" {
		// Clearnet link
		result.ClearnetLinks = append(result.ClearnetLinks, link)
	} else {
		// Relative link (internal) - shouldn't happen after resolveURL
		result.InternalLinks = append(result.InternalLinks, link)
	}
}

// extractEmails extracts email addresses from text.
//
// Design decision: We use a permissive regex rather than strict RFC 5322
// because:
//  1. We want to catch obfuscated emails (e.g., "user at domain dot com")
//  2. False positives are acceptable for security auditing
//  3. Strict parsing would miss many real-world cases
var emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

func (p *Parser) extractEmails(text string) []string {
	matches := emailRegex.FindAllString(text, -1)

	// Deduplicate
	seen := make(map[string]bool)
	unique := make([]string, 0)
	for _, email := range matches {
		lower := strings.ToLower(email)
		if !seen[lower] {
			seen[lower] = true
			unique = append(unique, lower)
		}
	}

	return unique
}

// extractOnionAddresses extracts .onion addresses from text.
//
// This captures both v2 (16 char) and v3 (56 char) onion addresses.
// We look for addresses even when not in URLs, as they might be mentioned in text.
var onionRegex = regexp.MustCompile(`[a-z2-7]{16,56}\.onion`)

func (p *Parser) extractOnionAddresses(text string) []string {
	matches := onionRegex.FindAllString(strings.ToLower(text), -1)

	// Deduplicate
	seen := make(map[string]bool)
	unique := make([]string, 0)
	for _, addr := range matches {
		if !seen[addr] {
			seen[addr] = true
			unique = append(unique, addr)
		}
	}

	return unique
}

// getAttr retrieves an attribute value from an HTML node.
func getAttr(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}
