package deanon

import (
	"context"
	"regexp"
	"strings"

	"github.com/nao1215/onionscan/internal/model"
)

// PrivateKeyAnalyzer detects exposed private key material.
// Finding Tor private keys, SSL/TLS private keys, or other
// cryptographic secrets on a hidden service is critical.
//
// This analyzer checks for:
//   - Tor v3 hidden service private keys (hs_ed25519_secret_key)
//   - Tor v2 hidden service private keys (private_key)
//   - PEM-encoded private keys (RSA, EC, etc.)
//   - SSH private keys
//   - PGP private key blocks
type PrivateKeyAnalyzer struct {
	// patterns contains compiled regex patterns for detection
	patterns []*privateKeyPattern
}

// privateKeyPattern holds a pattern and its metadata.
type privateKeyPattern struct {
	name        string
	description string
	severity    model.Severity
	pattern     *regexp.Regexp
}

// NewPrivateKeyAnalyzer creates a new PrivateKeyAnalyzer.
func NewPrivateKeyAnalyzer() *PrivateKeyAnalyzer {
	return &PrivateKeyAnalyzer{
		patterns: []*privateKeyPattern{
			// Tor v3 Hidden Service Private Key
			{
				name:        "tor_v3_private_key",
				description: "A Tor v3 hidden service private key (ed25519) was found. This allows anyone to impersonate the hidden service.",
				severity:    model.SeverityCritical,
				pattern:     regexp.MustCompile(`(?i)(?:== ed25519v1-secret:|hs_ed25519_secret_key|ED25519 PRIVATE KEY)`),
			},

			// Tor v2 Hidden Service Private Key (legacy)
			{
				name:        "tor_v2_private_key",
				description: "A Tor v2 hidden service private key (RSA) was found. This allows anyone to impersonate the hidden service.",
				severity:    model.SeverityCritical,
				pattern:     regexp.MustCompile(`(?i)RSA1024.*?PRIVATE KEY`),
			},

			// Generic RSA Private Key
			{
				name:        "rsa_private_key",
				description: "An RSA private key was found. This could be used to decrypt communications or impersonate a service.",
				severity:    model.SeverityCritical,
				pattern:     regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
			},

			// EC Private Key
			{
				name:        "ec_private_key",
				description: "An EC private key was found. This could be used to decrypt communications or sign data.",
				severity:    model.SeverityCritical,
				pattern:     regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
			},

			// Generic Private Key (PKCS#8)
			{
				name:        "pkcs8_private_key",
				description: "A PKCS#8 private key was found. This is a critical security exposure.",
				severity:    model.SeverityCritical,
				pattern:     regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
			},

			// Encrypted Private Key (PKCS#8)
			{
				name:        "encrypted_private_key",
				description: "An encrypted private key was found. While encrypted, exposure still represents a risk.",
				severity:    model.SeverityHigh,
				pattern:     regexp.MustCompile(`-----BEGIN ENCRYPTED PRIVATE KEY-----`),
			},

			// DSA Private Key
			{
				name:        "dsa_private_key",
				description: "A DSA private key was found. This could be used for signing.",
				severity:    model.SeverityCritical,
				pattern:     regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`),
			},

			// OpenSSH Private Key (new format)
			{
				name:        "openssh_private_key",
				description: "An OpenSSH private key was found. This could allow unauthorized SSH access.",
				severity:    model.SeverityCritical,
				pattern:     regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
			},

			// PuTTY Private Key
			{
				name:        "putty_private_key",
				description: "A PuTTY private key was found. This could allow unauthorized SSH access.",
				severity:    model.SeverityCritical,
				pattern:     regexp.MustCompile(`PuTTY-User-Key-File-\d+:`),
			},

			// PGP Private Key Block
			{
				name:        "pgp_private_key",
				description: "A PGP private key block was found. This could allow decryption of encrypted communications.",
				severity:    model.SeverityCritical,
				pattern:     regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
			},

			// AWS Access Key ID (high entropy strings that could be keys)
			{
				name:        "aws_access_key",
				description: "An AWS Access Key ID was found. This could allow unauthorized access to AWS resources.",
				severity:    model.SeverityHigh,
				pattern:     regexp.MustCompile(`(?i)(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}`),
			},

			// AWS Secret Key
			{
				name:        "aws_secret_key",
				description: "A potential AWS Secret Access Key was found. Combined with an Access Key ID, this allows AWS access.",
				severity:    model.SeverityCritical,
				pattern:     regexp.MustCompile(`(?i)aws[_\-\.]?secret[_\-\.]?(?:access)?[_\-\.]?key[^\w]*[\'\"][A-Za-z0-9/+=]{40}[\'\"]`),
			},

			// GitHub Token
			{
				name:        "github_token",
				description: "A GitHub personal access token was found. This could allow unauthorized repository access.",
				severity:    model.SeverityHigh,
				pattern:     regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,255}`),
			},

			// Generic API Key pattern
			{
				name:        "api_key",
				description: "A potential API key was found. This could allow unauthorized access to external services.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:api[_\-\.]?key|apikey)[^\w]*[\'\"][A-Za-z0-9_\-]{20,}[\'\"]`),
			},

			// Base64-encoded key-like data (potential encoded keys)
			{
				name:        "base64_key_data",
				description: "A base64-encoded string that may contain key material was found.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?:secret|private|key)[^\w]*[\'\"]([A-Za-z0-9+/]{40,}={0,2})[\'\"]`),
			},
		},
	}
}

// Name returns the analyzer name.
func (a *PrivateKeyAnalyzer) Name() string {
	return "privatekey"
}

// Category returns the analyzer category.
func (a *PrivateKeyAnalyzer) Category() string {
	return "secrets"
}

// Analyze searches for private key material in crawled content.
func (a *PrivateKeyAnalyzer) Analyze(ctx context.Context, data *AnalysisData) ([]model.Finding, error) {
	findings := make([]model.Finding, 0)
	foundKeys := make(map[string]bool) // Deduplicate findings

	for _, page := range data.Pages {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Search in page content
		pageFindings := a.searchContent(page.Snapshot, page.URL)
		for _, f := range pageFindings {
			key := f.Type + "|" + f.Value
			if !foundKeys[key] {
				foundKeys[key] = true
				findings = append(findings, f)
			}
		}

		// Also search in raw HTML
		if len(page.Raw) > 0 {
			rawStr := string(page.Raw)
			if rawStr != page.Snapshot {
				rawFindings := a.searchContent(rawStr, page.URL)
				for _, f := range rawFindings {
					key := f.Type + "|" + f.Value
					if !foundKeys[key] {
						foundKeys[key] = true
						findings = append(findings, f)
					}
				}
			}
		}
	}

	return findings, nil
}

// searchContent searches for private key patterns in content.
func (a *PrivateKeyAnalyzer) searchContent(content, location string) []model.Finding {
	findings := make([]model.Finding, 0)

	for _, p := range a.patterns {
		if matches := p.pattern.FindAllString(content, 5); len(matches) > 0 {
			// Sanitize the match value (don't expose the actual key)
			value := a.sanitizeKeyValue(matches[0], p.name)

			findings = append(findings, model.Finding{
				Type:         p.name,
				Title:        a.titleForPattern(p.name),
				Description:  p.description,
				Severity:     p.severity,
				SeverityText: p.severity.String(),
				Value:        value,
				Location:     location,
			})
		}
	}

	return findings
}

// sanitizeKeyValue returns a safe representation of the key.
// We don't want to expose the actual key material.
func (a *PrivateKeyAnalyzer) sanitizeKeyValue(value, keyType string) string {
	// For PEM-style keys, just show the header
	if strings.Contains(value, "-----BEGIN") {
		parts := strings.SplitN(value, "\n", 2)
		if len(parts) > 0 {
			return parts[0] + "..."
		}
	}

	// For AWS keys, partially redact
	if strings.HasPrefix(keyType, "aws") {
		if len(value) > 10 {
			return value[:10] + "...[REDACTED]"
		}
	}

	// For other keys, show type indicator only
	if len(value) > 20 {
		return value[:20] + "...[REDACTED]"
	}

	return value
}

// titleForPattern returns a human-readable title for a pattern type.
func (a *PrivateKeyAnalyzer) titleForPattern(patternName string) string {
	titles := map[string]string{
		"tor_v3_private_key":    "Tor v3 Hidden Service Private Key Exposed",
		"tor_v2_private_key":    "Tor v2 Hidden Service Private Key Exposed",
		"rsa_private_key":       "RSA Private Key Exposed",
		"ec_private_key":        "EC Private Key Exposed",
		"pkcs8_private_key":     "PKCS#8 Private Key Exposed",
		"encrypted_private_key": "Encrypted Private Key Found",
		"dsa_private_key":       "DSA Private Key Exposed",
		"openssh_private_key":   "OpenSSH Private Key Exposed",
		"putty_private_key":     "PuTTY Private Key Exposed",
		"pgp_private_key":       "PGP Private Key Exposed",
		"aws_access_key":        "AWS Access Key ID Found",
		"aws_secret_key":        "AWS Secret Access Key Exposed",
		"github_token":          "GitHub Token Exposed",
		"api_key":               "API Key Exposed",
		"base64_key_data":       "Potential Encoded Key Data Found",
	}

	if title, ok := titles[patternName]; ok {
		return title
	}
	return "Private Key Material Exposed"
}

// Ensure PrivateKeyAnalyzer implements CheckAnalyzer.
var _ CheckAnalyzer = (*PrivateKeyAnalyzer)(nil)
