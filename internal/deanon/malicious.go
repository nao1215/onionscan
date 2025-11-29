package deanon

import (
	"context"
	"regexp"
	"strings"

	"github.com/nao1215/onionscan/internal/model"
)

// MaliciousAnalyzer detects potentially malicious content that could
// deanonymize or attack visitors.
//
// This analyzer checks for:
//   - JavaScript obfuscation (potential malware)
//   - Forms submitting to external URLs
//   - Suspicious redirects to clearnet
//   - Hidden iframes (tracking/malware vectors)
//   - Debug artifacts and error disclosures
type MaliciousAnalyzer struct {
	// obfuscation patterns that indicate suspicious code
	obfuscationPatterns []*regexp.Regexp
}

// NewMaliciousAnalyzer creates a new MaliciousAnalyzer.
func NewMaliciousAnalyzer() *MaliciousAnalyzer {
	return &MaliciousAnalyzer{
		obfuscationPatterns: []*regexp.Regexp{
			// eval with encoded strings
			regexp.MustCompile(`eval\s*\(\s*(atob|unescape|decodeURIComponent|String\.fromCharCode)`),

			// Long hex or base64 strings (potential encoded payloads)
			regexp.MustCompile(`(\\x[0-9a-fA-F]{2}){10,}`),
			regexp.MustCompile(`['"][A-Za-z0-9+/=]{100,}['"]`),

			// document.write with encoded content
			regexp.MustCompile(`document\.write\s*\(\s*(unescape|atob|decodeURIComponent)`),

			// Suspicious function constructor
			regexp.MustCompile(`new\s+Function\s*\(\s*['"][^'"]{50,}['"]\s*\)`),

			// Packed JavaScript patterns
			regexp.MustCompile(`eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)`),

			// JSFuck-like obfuscation
			regexp.MustCompile(`\[\s*!\s*\+\s*\[\s*\]\s*\]`),
			regexp.MustCompile(`\(\s*!\s*\[\s*\]\s*\+\s*\[\s*\]\s*\)`),

			// Suspicious character code operations
			regexp.MustCompile(`String\.fromCharCode\s*\([^)]{50,}\)`),
		},
	}
}

// Name returns the analyzer name.
func (a *MaliciousAnalyzer) Name() string {
	return "malicious"
}

// Category returns the analyzer category.
func (a *MaliciousAnalyzer) Category() string {
	return categoryAttack
}

// Analyze searches for malicious patterns in page content.
func (a *MaliciousAnalyzer) Analyze(ctx context.Context, data *AnalysisData) ([]model.Finding, error) {
	findings := make([]model.Finding, 0)

	for _, page := range data.Pages {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Check for JavaScript obfuscation
		findings = append(findings, a.checkObfuscation(page)...)

		// Check for forms submitting to external URLs
		findings = append(findings, a.checkFormActions(page)...)

		// Check for suspicious redirects
		findings = append(findings, a.checkRedirects(page)...)

		// Check for hidden iframes
		findings = append(findings, a.checkHiddenIframes(page)...)

		// Check for debug artifacts
		findings = append(findings, a.checkDebugArtifacts(page)...)

		// Check for error disclosures
		findings = append(findings, a.checkErrorDisclosure(page)...)
	}

	return findings, nil
}

// checkObfuscation detects obfuscated JavaScript code.
func (a *MaliciousAnalyzer) checkObfuscation(page *model.Page) []model.Finding {
	findings := make([]model.Finding, 0)

	// Use the page snapshot which includes all text content
	content := page.Snapshot

	for _, pattern := range a.obfuscationPatterns {
		if pattern.MatchString(content) {
			findings = append(findings, model.Finding{
				Type:         "js_obfuscation",
				Title:        "Suspicious JavaScript Obfuscation",
				Description:  "Obfuscated JavaScript code was detected. This pattern is commonly used to hide malicious code such as credential stealers, exploit kits, or tracking scripts.",
				Severity:     model.SeverityHigh,
				SeverityText: model.SeverityHigh.String(),
				Value:        pattern.String()[:min(50, len(pattern.String()))],
				Location:     page.URL,
			})
			// Only report one obfuscation finding per page
			break
		}
	}

	return findings
}

// checkFormActions detects forms that submit to external URLs.
func (a *MaliciousAnalyzer) checkFormActions(page *model.Page) []model.Finding {
	findings := make([]model.Finding, 0)

	for _, form := range page.Forms {
		if form.Action == "" {
			continue
		}

		action := strings.ToLower(form.Action)

		// Check if form submits to a non-onion URL
		if (strings.HasPrefix(action, "http://") || strings.HasPrefix(action, "https://")) &&
			!strings.Contains(action, ".onion") {
			findings = append(findings, model.Finding{
				Type:         "form_action_leak",
				Title:        "Form Submits to External URL",
				Description:  "A form on this page submits data to a non-.onion URL. This leaks visitor IP addresses and form data to external servers.",
				Severity:     model.SeverityHigh,
				SeverityText: model.SeverityHigh.String(),
				Value:        form.Action,
				Location:     page.URL,
			})
		}
	}

	return findings
}

// checkRedirects detects suspicious redirects to clearnet.
func (a *MaliciousAnalyzer) checkRedirects(page *model.Page) []model.Finding {
	findings := make([]model.Finding, 0)
	content := page.Snapshot

	// Check meta refresh redirects
	metaRefreshPattern := regexp.MustCompile(`(?i)<meta[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']?\d+\s*;\s*url\s*=\s*["']?([^"'>]+)`)
	matches := metaRefreshPattern.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			url := strings.ToLower(match[1])
			if (strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")) &&
				!strings.Contains(url, ".onion") {
				findings = append(findings, model.Finding{
					Type:         "suspicious_redirect",
					Title:        "Meta Refresh Redirect to Clearnet",
					Description:  "A meta refresh tag redirects to a non-.onion URL. This could deanonymize visitors.",
					Severity:     model.SeverityHigh,
					SeverityText: model.SeverityHigh.String(),
					Value:        match[1],
					Location:     page.URL,
				})
			}
		}
	}

	// Check JavaScript redirects
	jsRedirectPatterns := []string{
		`window\.location\s*=\s*["']([^"']+)["']`,
		`location\.href\s*=\s*["']([^"']+)["']`,
		`location\.replace\s*\(\s*["']([^"']+)["']\s*\)`,
	}

	for _, patternStr := range jsRedirectPatterns {
		pattern := regexp.MustCompile(patternStr)
		matches := pattern.FindAllStringSubmatch(content, -1)

		for _, match := range matches {
			if len(match) > 1 {
				url := strings.ToLower(match[1])
				if (strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")) &&
					!strings.Contains(url, ".onion") {
					findings = append(findings, model.Finding{
						Type:         "suspicious_redirect",
						Title:        "JavaScript Redirect to Clearnet",
						Description:  "JavaScript code redirects to a non-.onion URL. This could deanonymize visitors.",
						Severity:     model.SeverityHigh,
						SeverityText: model.SeverityHigh.String(),
						Value:        match[1],
						Location:     page.URL,
					})
				}
			}
		}
	}

	return findings
}

// checkHiddenIframes detects hidden iframes that could be malicious.
func (a *MaliciousAnalyzer) checkHiddenIframes(page *model.Page) []model.Finding {
	findings := make([]model.Finding, 0)
	content := page.Snapshot

	// Patterns for hidden iframes
	hiddenIframePatterns := []*regexp.Regexp{
		// Zero size iframes
		regexp.MustCompile(`(?i)<iframe[^>]*(?:width\s*=\s*["']?0|height\s*=\s*["']?0)[^>]*>`),

		// Visibility hidden
		regexp.MustCompile(`(?i)<iframe[^>]*style\s*=\s*["'][^"']*visibility\s*:\s*hidden[^"']*["'][^>]*>`),

		// Display none
		regexp.MustCompile(`(?i)<iframe[^>]*style\s*=\s*["'][^"']*display\s*:\s*none[^"']*["'][^>]*>`),

		// Off-screen positioning
		regexp.MustCompile(`(?i)<iframe[^>]*style\s*=\s*["'][^"']*(?:left|top)\s*:\s*-\d{3,}[^"']*["'][^>]*>`),
	}

	for _, pattern := range hiddenIframePatterns {
		if pattern.MatchString(content) {
			findings = append(findings, model.Finding{
				Type:         "hidden_iframe",
				Title:        "Hidden Iframe Detected",
				Description:  "A hidden iframe was detected. Hidden iframes can be used for clickjacking, drive-by downloads, IP leaking, or ad fraud.",
				Severity:     model.SeverityHigh,
				SeverityText: model.SeverityHigh.String(),
				Value:        "Hidden iframe found",
				Location:     page.URL,
			})
			// Only report once per page
			break
		}
	}

	// Check for iframes pointing to external URLs
	externalIframePattern := regexp.MustCompile(`(?i)<iframe[^>]*src\s*=\s*["']?(https?://[^"'\s>]+)["']?[^>]*>`)
	matches := externalIframePattern.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			url := strings.ToLower(match[1])
			if !strings.Contains(url, ".onion") {
				findings = append(findings, model.Finding{
					Type:         "external_iframe",
					Title:        "External Iframe Detected",
					Description:  "An iframe loads content from a non-.onion URL. This exposes visitor IP addresses to the external server.",
					Severity:     model.SeverityHigh,
					SeverityText: model.SeverityHigh.String(),
					Value:        match[1],
					Location:     page.URL,
				})
			}
		}
	}

	return findings
}

// checkDebugArtifacts detects debug information that shouldn't be in production.
func (a *MaliciousAnalyzer) checkDebugArtifacts(page *model.Page) []model.Finding {
	findings := make([]model.Finding, 0)
	content := page.Snapshot

	// Source map references
	if strings.Contains(content, "sourceMappingURL") {
		findings = append(findings, model.Finding{
			Type:         "debug_sourcemap",
			Title:        "Source Map Reference Found",
			Description:  "A JavaScript source map reference was found. Source maps can expose original source code and development environment details.",
			Severity:     model.SeverityMedium,
			SeverityText: model.SeverityMedium.String(),
			Value:        "sourceMappingURL found",
			Location:     page.URL,
		})
	}

	// Console.log statements
	consolePattern := regexp.MustCompile(`console\.(log|debug|info|warn|error)\s*\([^)]+\)`)
	if consolePattern.MatchString(content) {
		findings = append(findings, model.Finding{
			Type:         "debug_console",
			Title:        "Console Debug Statements Found",
			Description:  "Console debugging statements were found. These may expose sensitive information or development details.",
			Severity:     model.SeverityLow,
			SeverityText: model.SeverityLow.String(),
			Value:        "console.* statements found",
			Location:     page.URL,
		})
	}

	// HTML comments with sensitive info
	commentPatterns := []string{
		`<!--[^>]*(?:TODO|FIXME|XXX|HACK|DEBUG)[^>]*-->`,
		`<!--[^>]*(?:password|secret|key|token|api)[^>]*-->`,
		`<!--[^>]*(?:admin|root|user)[^>]*-->`,
	}

	for _, patternStr := range commentPatterns {
		pattern := regexp.MustCompile(`(?i)` + patternStr)
		if pattern.MatchString(content) {
			findings = append(findings, model.Finding{
				Type:         "debug_comments",
				Title:        "Sensitive HTML Comments Found",
				Description:  "HTML comments containing potentially sensitive development notes were found.",
				Severity:     model.SeverityMedium,
				SeverityText: model.SeverityMedium.String(),
				Value:        "Sensitive comments found",
				Location:     page.URL,
			})
			break
		}
	}

	return findings
}

// checkErrorDisclosure detects error messages that reveal server info.
func (a *MaliciousAnalyzer) checkErrorDisclosure(page *model.Page) []model.Finding {
	findings := make([]model.Finding, 0)
	content := page.Snapshot

	// Stack trace patterns
	stackTracePatterns := []*regexp.Regexp{
		// PHP errors
		regexp.MustCompile(`(?i)(?:Fatal error|Parse error|Warning|Notice):\s+[^\n]+\s+in\s+(/[^\s]+)\s+on\s+line\s+\d+`),

		// Python tracebacks
		regexp.MustCompile(`(?i)Traceback \(most recent call last\):`),
		regexp.MustCompile(`File "([^"]+)", line \d+, in`),

		// Java/Spring exceptions
		regexp.MustCompile(`(?i)(?:java\.|javax\.|org\.springframework\.)[a-zA-Z.]+Exception`),

		// .NET exceptions
		regexp.MustCompile(`(?i)System\.[A-Za-z]+Exception:`),
		regexp.MustCompile(`at [A-Za-z.]+\([^)]*\) in [^:]+:\s*line \d+`),

		// Node.js errors
		regexp.MustCompile(`at [A-Za-z.]+\s+\([^)]+\.js:\d+:\d+\)`),

		// Ruby errors
		regexp.MustCompile(`(?i)\([^)]+\.rb:\d+:in `),

		// Generic path disclosure
		regexp.MustCompile(`(?:\/var\/www|\/home\/[a-zA-Z0-9]+|C:\\\\[a-zA-Z0-9]+)`),
	}

	for _, pattern := range stackTracePatterns {
		if pattern.MatchString(content) {
			findings = append(findings, model.Finding{
				Type:         "error_disclosure",
				Title:        "Error Message or Stack Trace Exposed",
				Description:  "An error message or stack trace was found that reveals server paths, framework information, or internal details. This helps attackers understand the server environment.",
				Severity:     model.SeverityHigh,
				SeverityText: model.SeverityHigh.String(),
				Value:        "Error/stack trace exposed",
				Location:     page.URL,
			})
			// Only report once per page
			break
		}
	}

	return findings
}
