package deanon

import (
	"context"
	"regexp"
	"strings"

	"github.com/nao1215/onionscan/internal/model"
)

// EmailAnalyzer detects email addresses in page content.
// Email addresses are significant deanonymization vectors as they
// often contain real names or can be traced to individuals.
//
// Design decision: We implement a separate analyzer for emails rather
// than combining it with other identity checks because:
//  1. Email detection has unique regex requirements
//  2. Emails have special handling needs (deduplication, domain analysis)
//  3. Severity varies based on where the email was found
type EmailAnalyzer struct {
	// emailRegex matches email addresses in text.
	emailRegex *regexp.Regexp

	// suspiciousDomains are email domains that are particularly identifying.
	// Personal domains or work emails are more significant than generic ones.
	suspiciousDomains []string
}

// NewEmailAnalyzer creates a new EmailAnalyzer.
func NewEmailAnalyzer() *EmailAnalyzer {
	return &EmailAnalyzer{
		// Standard email regex that catches most valid addresses
		emailRegex:        regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
		suspiciousDomains: []string{
			// Generic free email providers are less identifying
			// We flag non-free email domains as more suspicious
		},
	}
}

// Name returns the analyzer name.
func (a *EmailAnalyzer) Name() string {
	return "email"
}

// Category returns the analyzer category.
func (a *EmailAnalyzer) Category() string {
	return CategoryIdentity
}

// Analyze searches for email addresses in all pages.
func (a *EmailAnalyzer) Analyze(ctx context.Context, data *AnalysisData) ([]model.Finding, error) {
	findings := make([]model.Finding, 0)
	seenEmails := make(map[string]bool)

	for _, page := range data.Pages {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Search in page snapshot
		emails := a.emailRegex.FindAllString(page.Snapshot, -1)

		for _, email := range emails {
			email = strings.ToLower(email)

			// Skip already seen
			if seenEmails[email] {
				continue
			}
			seenEmails[email] = true

			// Determine severity based on email domain
			severity := a.assessEmailSeverity(email)

			findings = append(findings, model.Finding{
				Type:         "email",
				Title:        "Email Address Found",
				Description:  "An email address was found in page content. This could be used to identify the operator.",
				Severity:     severity,
				SeverityText: severity.String(),
				Value:        email,
				Location:     page.URL,
			})

			// Also add to report's anonymity findings
			if data.Report != nil {
				data.Report.AnonymityReport.AddEmailAddress(email)
			}
		}
	}

	return findings, nil
}

// assessEmailSeverity determines the severity of an email finding.
//
// Design decision: We rate email severity based on domain because:
//  1. Personal domains (john@johndoe.com) are highly identifying
//  2. Corporate emails reveal employer information
//  3. Free email services (gmail, protonmail) are less specific
func (a *EmailAnalyzer) assessEmailSeverity(email string) model.Severity {
	// Extract domain
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return model.SeverityMedium
	}
	domain := strings.ToLower(parts[1])

	// Free email providers are less identifying but still noteworthy
	freeProviders := []string{
		"gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
		"protonmail.com", "proton.me", "tutanota.com", "tutamail.com",
		"aol.com", "icloud.com", "mail.com", "yandex.com",
	}

	for _, provider := range freeProviders {
		if domain == provider {
			return model.SeverityMedium
		}
	}

	// Corporate or personal domains are more identifying
	return model.SeverityHigh
}
