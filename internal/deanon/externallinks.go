package deanon

import (
	"context"
	"net/url"
	"strings"

	"github.com/nao1215/onionscan/internal/model"
)

// ExternalLinkAnalyzer detects links and references to external resources.
// External links can be deanonymization vectors because:
//  1. Clearnet links may reveal associated domains
//  2. Resource loading from external sources exposes visitor IPs
//  3. Cross-site references can correlate operators
//
// Design decision: We analyze external links in both HTML and headers because:
//  1. CSP headers define allowed external sources
//  2. HTML may reference external scripts, images, fonts
//  3. Even commented-out links are informative
type ExternalLinkAnalyzer struct{}

// NewExternalLinkAnalyzer creates a new ExternalLinkAnalyzer.
func NewExternalLinkAnalyzer() *ExternalLinkAnalyzer {
	return &ExternalLinkAnalyzer{}
}

// Name returns the analyzer name.
func (a *ExternalLinkAnalyzer) Name() string {
	return "externallinks"
}

// Category returns the analyzer category.
func (a *ExternalLinkAnalyzer) Category() string {
	return CategoryCorrelation
}

// Analyze searches for external links and resource references.
func (a *ExternalLinkAnalyzer) Analyze(ctx context.Context, data *AnalysisData) ([]model.Finding, error) {
	findings := make([]model.Finding, 0)
	seenDomains := make(map[string]bool)

	for _, page := range data.Pages {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Analyze external anchors (links to other sites)
		findings = append(findings, a.analyzeAnchors(page, seenDomains, data)...)

		// Analyze external scripts
		findings = append(findings, a.analyzeScripts(page, seenDomains)...)

		// Analyze external images
		findings = append(findings, a.analyzeImages(page, seenDomains)...)

		// Analyze CSP header for external domains
		if page.CSP != nil {
			findings = append(findings, a.analyzeCSP(page, seenDomains)...)
		}
	}

	return findings, nil
}

// analyzeAnchors checks for clearnet links in anchor elements.
func (a *ExternalLinkAnalyzer) analyzeAnchors(page *model.Page, seen map[string]bool, data *AnalysisData) []model.Finding {
	findings := make([]model.Finding, 0)

	for _, anchor := range page.Anchors {
		if anchor.Source == "" {
			continue
		}

		domain := a.extractDomain(anchor.Source)
		if domain == "" {
			continue
		}

		// Skip onion addresses
		if strings.HasSuffix(domain, ".onion") {
			continue
		}

		// Skip already seen
		if seen[domain] {
			continue
		}
		seen[domain] = true

		severity := a.assessLinkSeverity(domain)

		finding := model.Finding{
			Type:         "clearnet_link",
			Title:        "Clearnet Link Found",
			Description:  "A link to a clearnet (non-onion) website was found. This may indicate a relationship between the onion service and the clearnet domain.",
			Severity:     severity,
			SeverityText: severity.String(),
			Value:        domain,
			Location:     page.URL,
		}
		findings = append(findings, finding)

		// Add to report
		if data.Report != nil {
			data.Report.AnonymityReport.AddRelatedClearnetDomain(domain)
		}
	}

	return findings
}

// analyzeScripts checks for external script sources.
func (a *ExternalLinkAnalyzer) analyzeScripts(page *model.Page, seen map[string]bool) []model.Finding {
	findings := make([]model.Finding, 0)

	for _, script := range page.Scripts {
		if script.Source == "" {
			continue
		}

		domain := a.extractDomain(script.Source)
		if domain == "" || strings.HasSuffix(domain, ".onion") {
			continue
		}

		key := "script:" + domain
		if seen[key] {
			continue
		}
		seen[key] = true

		// External scripts are higher severity because they can track visitors
		findings = append(findings, model.Finding{
			Type:         "external_script",
			Title:        "External Script Loaded",
			Description:  "A script is loaded from a clearnet domain. This allows the external server to track visitors by IP address.",
			Severity:     model.SeverityHigh,
			SeverityText: model.SeverityHigh.String(),
			Value:        script.Source,
			Location:     page.URL,
		})
	}

	return findings
}

// analyzeImages checks for external image sources.
func (a *ExternalLinkAnalyzer) analyzeImages(page *model.Page, seen map[string]bool) []model.Finding {
	findings := make([]model.Finding, 0)

	for _, img := range page.Images {
		if img.Source == "" {
			continue
		}

		domain := a.extractDomain(img.Source)
		if domain == "" || strings.HasSuffix(domain, ".onion") {
			continue
		}

		key := "image:" + domain
		if seen[key] {
			continue
		}
		seen[key] = true

		// External images can be used for tracking
		findings = append(findings, model.Finding{
			Type:         "external_image",
			Title:        "External Image Loaded",
			Description:  "An image is loaded from a clearnet domain. This exposes visitor IP addresses to the external server.",
			Severity:     model.SeverityHigh,
			SeverityText: model.SeverityHigh.String(),
			Value:        img.Source,
			Location:     page.URL,
		})
	}

	return findings
}

// analyzeCSP checks Content-Security-Policy for external domains.
func (a *ExternalLinkAnalyzer) analyzeCSP(page *model.Page, seen map[string]bool) []model.Finding {
	findings := make([]model.Finding, 0)

	if page.CSP == nil {
		return findings
	}

	// Check for external domains in CSP
	for _, domain := range page.CSP.ExternalDomains {
		if seen["csp:"+domain] {
			continue
		}
		seen["csp:"+domain] = true

		// Skip common CDNs that are less identifying
		if a.isCommonCDN(domain) {
			findings = append(findings, model.Finding{
				Type:         "csp_cdn",
				Title:        "Common CDN in CSP",
				Description:  "A common CDN is referenced in the Content-Security-Policy.",
				Severity:     model.SeverityInfo,
				SeverityText: model.SeverityInfo.String(),
				Value:        domain,
				Location:     page.URL,
			})
		} else {
			findings = append(findings, model.Finding{
				Type:         "csp_external_domain",
				Title:        "External Domain in CSP",
				Description:  "The Content-Security-Policy allows loading resources from a clearnet domain.",
				Severity:     model.SeverityMedium,
				SeverityText: model.SeverityMedium.String(),
				Value:        domain,
				Location:     page.URL,
			})
		}
	}

	// Check for report-uri (sends data to external endpoint)
	if page.CSP.ReportURI != "" {
		findings = append(findings, model.Finding{
			Type:         "csp_report_uri",
			Title:        "CSP Report URI Configured",
			Description:  "The Content-Security-Policy sends violation reports to an external endpoint. This could reveal visitor information.",
			Severity:     model.SeverityHigh,
			SeverityText: model.SeverityHigh.String(),
			Value:        page.CSP.ReportURI,
			Location:     page.URL,
		})
	}

	return findings
}

// extractDomain extracts the domain from a URL.
func (a *ExternalLinkAnalyzer) extractDomain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	// Skip relative URLs
	if u.Host == "" {
		return ""
	}

	return strings.ToLower(u.Host)
}

// assessLinkSeverity determines the severity of a clearnet link.
//
// Design decision: Severity varies by link target because:
//  1. Social media links may reveal operator identity
//  2. Personal domains strongly correlate ownership
//  3. Generic sites are less identifying
func (a *ExternalLinkAnalyzer) assessLinkSeverity(domain string) model.Severity {
	// Social media links are higher severity
	socialDomains := []string{
		"twitter.com", "x.com", "facebook.com", "instagram.com",
		"linkedin.com", "github.com", "reddit.com", "youtube.com",
	}

	for _, social := range socialDomains {
		if strings.Contains(domain, social) {
			return model.SeverityHigh
		}
	}

	return model.SeverityMedium
}

// isCommonCDN checks if a domain is a common CDN.
func (a *ExternalLinkAnalyzer) isCommonCDN(domain string) bool {
	cdns := []string{
		"cloudflare.com", "cloudflare-ipfs.com",
		"cdnjs.cloudflare.com",
		"jsdelivr.net",
		"unpkg.com",
		"googleapis.com",
		"gstatic.com",
		"bootstrapcdn.com",
		"maxcdn.bootstrapcdn.com",
		"fontawesome.com",
	}

	for _, cdn := range cdns {
		if strings.HasSuffix(domain, cdn) {
			return true
		}
	}

	return false
}
