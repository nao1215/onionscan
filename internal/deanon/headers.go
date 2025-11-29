package deanon

import (
	"context"
	"regexp"
	"strings"

	"github.com/nao1215/onionscan/internal/model"
)

// HeaderAnalyzer detects security header issues that could affect anonymity.
// Missing or misconfigured headers can lead to tracking, session hijacking,
// or other privacy risks.
//
// This analyzer checks for:
//   - ETag tracking (can be used to track users across sessions)
//   - Missing Content-Security-Policy (allows unauthorized resource loading)
//   - Insecure Cookie configuration (session hijacking risk)
//   - HSTS misconfigurations (can link onion to clearnet)
type HeaderAnalyzer struct{}

// NewHeaderAnalyzer creates a new HeaderAnalyzer.
func NewHeaderAnalyzer() *HeaderAnalyzer {
	return &HeaderAnalyzer{}
}

// Name returns the analyzer name.
func (a *HeaderAnalyzer) Name() string {
	return "headers"
}

// Category returns the analyzer category.
func (a *HeaderAnalyzer) Category() string {
	return "security"
}

// Analyze examines HTTP headers for security and privacy issues.
func (a *HeaderAnalyzer) Analyze(ctx context.Context, data *AnalysisData) ([]model.Finding, error) {
	findings := make([]model.Finding, 0)
	checkedPages := make(map[string]bool)

	for _, page := range data.Pages {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Only check each unique URL once
		if checkedPages[page.URL] {
			continue
		}
		checkedPages[page.URL] = true

		// Check ETag tracking
		findings = append(findings, a.checkETag(page)...)

		// Check CSP
		findings = append(findings, a.checkCSP(page)...)

		// Check cookies
		findings = append(findings, a.checkCookies(page)...)

		// Check HSTS
		findings = append(findings, a.checkHSTS(page)...)
	}

	return findings, nil
}

// checkETag detects ETag headers that could be used for tracking.
//
// ETags are HTTP caching headers that can be abused to track users
// across sessions, similar to cookies but harder to clear.
func (a *HeaderAnalyzer) checkETag(page *model.Page) []model.Finding {
	findings := make([]model.Finding, 0)

	etag := page.GetHeader("ETag")
	if etag == "" {
		return findings
	}

	// Long or unique ETags are more concerning
	severity := model.SeverityMedium
	if len(etag) > 20 {
		severity = model.SeverityHigh
	}

	findings = append(findings, model.Finding{
		Type:         "etag_tracking",
		Title:        "ETag Tracking Risk",
		Description:  "An ETag header was found that could be used to track users across sessions. ETags can function like supercookies, persisting even when cookies are cleared.",
		Severity:     severity,
		SeverityText: severity.String(),
		Value:        etag,
		Location:     page.URL,
	})

	return findings
}

// checkCSP detects missing or weak Content-Security-Policy headers.
//
// CSP helps prevent XSS and unauthorized resource loading. Missing CSP
// on an onion site allows attackers to inject tracking scripts.
func (a *HeaderAnalyzer) checkCSP(page *model.Page) []model.Finding {
	findings := make([]model.Finding, 0)

	csp := page.GetHeader("Content-Security-Policy")
	cspReportOnly := page.GetHeader("Content-Security-Policy-Report-Only")

	if csp == "" && cspReportOnly == "" {
		findings = append(findings, model.Finding{
			Type:         "csp_missing",
			Title:        "Missing Content Security Policy",
			Description:  "No Content-Security-Policy header was found. CSP helps prevent XSS attacks and unauthorized resource loading that could track visitors.",
			Severity:     model.SeverityMedium,
			SeverityText: model.SeverityMedium.String(),
			Value:        "No CSP header present",
			Location:     page.URL,
		})
		return findings
	}

	// Check for unsafe directives
	if csp != "" {
		if strings.Contains(csp, "'unsafe-inline'") {
			findings = append(findings, model.Finding{
				Type:         "csp_unsafe_inline",
				Title:        "CSP Allows Unsafe Inline Scripts",
				Description:  "The Content-Security-Policy allows 'unsafe-inline' scripts, which weakens XSS protection.",
				Severity:     model.SeverityMedium,
				SeverityText: model.SeverityMedium.String(),
				Value:        csp,
				Location:     page.URL,
			})
		}

		if strings.Contains(csp, "'unsafe-eval'") {
			findings = append(findings, model.Finding{
				Type:         "csp_unsafe_eval",
				Title:        "CSP Allows Unsafe Eval",
				Description:  "The Content-Security-Policy allows 'unsafe-eval', which can be exploited for code injection.",
				Severity:     model.SeverityMedium,
				SeverityText: model.SeverityMedium.String(),
				Value:        csp,
				Location:     page.URL,
			})
		}

		// Check for external domains in default-src or script-src
		if a.hasExternalDomains(csp) {
			findings = append(findings, model.Finding{
				Type:         "csp_external_allowed",
				Title:        "CSP Allows External Domains",
				Description:  "The Content-Security-Policy allows loading resources from external clearnet domains.",
				Severity:     model.SeverityMedium,
				SeverityText: model.SeverityMedium.String(),
				Value:        csp,
				Location:     page.URL,
			})
		}
	}

	return findings
}

// hasExternalDomains checks if CSP allows external (non-onion) domains.
func (a *HeaderAnalyzer) hasExternalDomains(csp string) bool {
	// Look for domain patterns that aren't 'self', *.onion, or data:
	domainPattern := regexp.MustCompile(`https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	matches := domainPattern.FindAllString(csp, -1)

	for _, match := range matches {
		if !strings.Contains(match, ".onion") {
			return true
		}
	}

	return false
}

// checkCookies detects insecure cookie configurations.
//
// Cookies without Secure, HttpOnly, or SameSite attributes can be
// intercepted or manipulated, compromising user sessions.
func (a *HeaderAnalyzer) checkCookies(page *model.Page) []model.Finding {
	findings := make([]model.Finding, 0)

	setCookie := page.GetHeader("Set-Cookie")
	if setCookie == "" {
		return findings
	}

	// Check for missing security attributes
	lowerCookie := strings.ToLower(setCookie)

	if !strings.Contains(lowerCookie, "httponly") {
		findings = append(findings, model.Finding{
			Type:         "cookie_no_httponly",
			Title:        "Cookie Missing HttpOnly Flag",
			Description:  "A cookie is set without the HttpOnly flag, making it accessible to JavaScript and vulnerable to XSS attacks.",
			Severity:     model.SeverityMedium,
			SeverityText: model.SeverityMedium.String(),
			Value:        a.sanitizeCookieValue(setCookie),
			Location:     page.URL,
		})
	}

	if !strings.Contains(lowerCookie, "samesite") {
		findings = append(findings, model.Finding{
			Type:         "cookie_no_samesite",
			Title:        "Cookie Missing SameSite Attribute",
			Description:  "A cookie is set without the SameSite attribute, potentially allowing CSRF attacks.",
			Severity:     model.SeverityLow,
			SeverityText: model.SeverityLow.String(),
			Value:        a.sanitizeCookieValue(setCookie),
			Location:     page.URL,
		})
	}

	// Check for session-like cookies that could enable tracking
	if a.isSessionCookie(setCookie) && !strings.Contains(lowerCookie, "expires") {
		// Session cookies without expiry persist until browser close
		// but long-lived session IDs can still track users
		if strings.Contains(lowerCookie, "max-age") {
			findings = append(findings, model.Finding{
				Type:         "session_linkability",
				Title:        "Persistent Session Cookie Detected",
				Description:  "A session cookie with a long lifetime was detected. This could enable user tracking across sessions.",
				Severity:     model.SeverityHigh,
				SeverityText: model.SeverityHigh.String(),
				Value:        a.sanitizeCookieValue(setCookie),
				Location:     page.URL,
			})
		}
	}

	return findings
}

// isSessionCookie checks if a cookie appears to be a session cookie.
func (a *HeaderAnalyzer) isSessionCookie(cookie string) bool {
	sessionPatterns := []string{
		"session", "sess", "sid", "phpsessid", "jsessionid",
		"asp.net_sessionid", "cfid", "cftoken",
	}

	lower := strings.ToLower(cookie)
	for _, pattern := range sessionPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// sanitizeCookieValue returns a safe representation of a cookie value.
// We don't want to expose actual session values in findings.
func (a *HeaderAnalyzer) sanitizeCookieValue(cookie string) string {
	// Only return the cookie name, not the value
	if idx := strings.Index(cookie, "="); idx != -1 {
		name := cookie[:idx]
		// Return name and first few chars of attributes
		rest := cookie[idx+1:]
		if semiIdx := strings.Index(rest, ";"); semiIdx != -1 {
			return name + "=<redacted>" + rest[semiIdx:]
		}
		return name + "=<redacted>"
	}
	return cookie
}

// checkHSTS detects HSTS configurations that could link identities.
//
// HSTS on an onion site can be used to:
// 1. Link the onion site to a clearnet mirror
// 2. Create HSTS supercookies for tracking
func (a *HeaderAnalyzer) checkHSTS(page *model.Page) []model.Finding {
	findings := make([]model.Finding, 0)

	hsts := page.GetHeader("Strict-Transport-Security")
	if hsts == "" {
		return findings
	}

	// HSTS on onion sites is suspicious since onion protocol
	// already provides transport security
	findings = append(findings, model.Finding{
		Type:         "hsts_on_onion",
		Title:        "HSTS Header on Onion Service",
		Description:  "An HSTS header was found on an onion service. This is unusual since .onion addresses already provide end-to-end encryption. This could indicate the site has a clearnet mirror or the header is being used for tracking.",
		Severity:     model.SeverityLow,
		SeverityText: model.SeverityLow.String(),
		Value:        hsts,
		Location:     page.URL,
	})

	// Check for preload directive which suggests clearnet presence
	if strings.Contains(strings.ToLower(hsts), "preload") {
		findings = append(findings, model.Finding{
			Type:         "hsts_preload",
			Title:        "HSTS Preload Directive Found",
			Description:  "The HSTS header includes the preload directive, strongly suggesting the site has a clearnet mirror in the HSTS preload list.",
			Severity:     model.SeverityMedium,
			SeverityText: model.SeverityMedium.String(),
			Value:        hsts,
			Location:     page.URL,
		})
	}

	return findings
}
