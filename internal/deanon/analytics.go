package deanon

import (
	"context"
	"regexp"
	"strings"

	"github.com/nao1215/onionscan/internal/model"
)

const (
	analyticsGoogleUA      = "google_analytics_ua"
	analyticsGoogleGA4     = "google_analytics_ga4"
	analyticsGoogleTag     = "google_tag_manager"
	analyticsGoogleAdSense = "google_adsense"
	analyticsFacebookPixel = "facebook_pixel"
)

// AnalyticsAnalyzer detects tracking and analytics IDs in page content.
// Analytics IDs are critical deanonymization vectors because they can
// be correlated across multiple sites to identify common operators.
//
// Design decision: Analytics detection is prioritized because:
//  1. Analytics IDs are unique and persistent
//  2. They can link onion services to clearnet sites
//  3. Historical data may exist in public databases
//  4. They indicate operator oversight (forgetting to remove tracking)
type AnalyticsAnalyzer struct {
	// patterns maps analytics type to detection regex.
	patterns map[string]*regexp.Regexp
}

// NewAnalyticsAnalyzer creates a new AnalyticsAnalyzer.
func NewAnalyticsAnalyzer() *AnalyticsAnalyzer {
	return &AnalyticsAnalyzer{
		patterns: map[string]*regexp.Regexp{
			// Google Analytics Universal (UA-XXXXX-Y)
			analyticsGoogleUA: regexp.MustCompile(`UA-\d{4,10}-\d{1,4}`),

			// Google Analytics 4 (G-XXXXXXXXXX)
			analyticsGoogleGA4: regexp.MustCompile(`G-[A-Z0-9]{10,12}`),

			// Google Tag Manager (GTM-XXXXXX)
			analyticsGoogleTag: regexp.MustCompile(`GTM-[A-Z0-9]{6,8}`),

			// Google AdSense (pub-XXXXXXXXXXXXXXXX)
			analyticsGoogleAdSense: regexp.MustCompile(`pub-\d{16}`),

			// Google Publisher Tag
			"google_publisher": regexp.MustCompile(`ca-pub-\d{16}`),

			// Facebook Pixel
			analyticsFacebookPixel: regexp.MustCompile(`fbq\s*\(\s*['"]init['"]\s*,\s*['"](\d{15,16})['"]`),

			// Yandex Metrica
			"yandex_metrica": regexp.MustCompile(`ym\s*\(\s*(\d{8,9})`),

			// Matomo/Piwik
			"matomo": regexp.MustCompile(`_paq\.push\s*\(\s*\[\s*['"]setSiteId['"]\s*,\s*['"]?(\d+)['"]?\s*\]`),

			// Microsoft Clarity
			"clarity": regexp.MustCompile(`clarity\s*\(\s*['"]set['"]\s*,\s*['"]([a-z0-9]+)['"]`),

			// Hotjar
			"hotjar": regexp.MustCompile(`hjid\s*:\s*(\d{6,7})`),

			// Amazon tracking
			"amazon_affiliate": regexp.MustCompile(`tag=([a-zA-Z0-9\-]+)-\d{2}`),
		},
	}
}

// Name returns the analyzer name.
func (a *AnalyticsAnalyzer) Name() string {
	return "analytics"
}

// Category returns the analyzer category.
func (a *AnalyticsAnalyzer) Category() string {
	return CategoryCorrelation
}

// Analyze searches for analytics IDs in all pages.
func (a *AnalyticsAnalyzer) Analyze(ctx context.Context, data *AnalysisData) ([]model.Finding, error) {
	findings := make([]model.Finding, 0)
	seenIDs := make(map[string]bool)

	for _, page := range data.Pages {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Search in page content
		content := page.Snapshot

		for analyticsType, pattern := range a.patterns {
			matches := pattern.FindAllStringSubmatch(content, -1)

			for _, match := range matches {
				// Get the full match or first capture group
				id := match[0]
				if len(match) > 1 && match[1] != "" {
					id = match[1]
				}

				key := analyticsType + ":" + id
				if seenIDs[key] {
					continue
				}
				seenIDs[key] = true

				severity := a.getSeverity(analyticsType)
				finding := model.Finding{
					Type:         "analytics_" + analyticsType,
					Title:        a.getTitle(analyticsType),
					Description:  a.getDescription(analyticsType),
					Severity:     severity,
					SeverityText: severity.String(),
					Value:        id,
					Location:     page.URL,
				}
				findings = append(findings, finding)

				// Add to report
				if data.Report != nil {
					data.Report.AnonymityReport.AddAnalyticsID(model.AnalyticsID{
						ID:   id,
						Type: analyticsType,
					})
				}
			}
		}
	}

	return findings, nil
}

// getTitle returns a human-readable title for the analytics type.
func (a *AnalyticsAnalyzer) getTitle(analyticsType string) string {
	titles := map[string]string{
		analyticsGoogleUA:      "Google Analytics UA ID Found",
		analyticsGoogleGA4:     "Google Analytics 4 ID Found",
		analyticsGoogleTag:     "Google Tag Manager ID Found",
		analyticsGoogleAdSense: "Google AdSense Publisher ID Found",
		"google_publisher":     "Google Publisher ID Found",
		analyticsFacebookPixel: "Facebook Pixel ID Found",
		"yandex_metrica":       "Yandex Metrica ID Found",
		"matomo":               "Matomo/Piwik Site ID Found",
		"clarity":              "Microsoft Clarity ID Found",
		"hotjar":               "Hotjar Site ID Found",
		"amazon_affiliate":     "Amazon Affiliate Tag Found",
	}

	if title, ok := titles[analyticsType]; ok {
		return title
	}
	return "Analytics ID Found"
}

// getDescription returns a description for the analytics type.
func (a *AnalyticsAnalyzer) getDescription(analyticsType string) string {
	descriptions := map[string]string{
		analyticsGoogleUA: "A Google Analytics Universal tracking ID was found. " +
			"This ID can be searched on services like SpyOnWeb to find other sites with the same owner.",
		analyticsGoogleGA4: "A Google Analytics 4 measurement ID was found. " +
			"This can be used to correlate this site with other properties.",
		analyticsGoogleTag: "A Google Tag Manager container ID was found. " +
			"This can be used to correlate this site with other properties managed by the same account.",
		analyticsGoogleAdSense: "A Google AdSense publisher ID was found. " +
			"This directly links to a Google account and can be used to find other sites.",
		analyticsFacebookPixel: "A Facebook Pixel ID was found. " +
			"This links to a Facebook Business account and may reveal identity.",
	}

	if desc, ok := descriptions[analyticsType]; ok {
		return desc
	}
	return "An analytics or tracking ID was found that could be used to correlate this service with other properties."
}

// getSeverity returns the severity for the analytics type.
//
// Design decision: Analytics IDs are rated high/critical because:
//  1. They provide direct correlation capability
//  2. Historical databases exist for tracking ID lookup
//  3. The same ID across sites proves common ownership
func (a *AnalyticsAnalyzer) getSeverity(analyticsType string) model.Severity {
	// AdSense/Publisher IDs are critical as they link to payment accounts
	if strings.Contains(analyticsType, "adsense") || strings.Contains(analyticsType, "publisher") {
		return model.SeverityCritical
	}

	// Most analytics IDs are high severity due to correlation risk
	return model.SeverityHigh
}
