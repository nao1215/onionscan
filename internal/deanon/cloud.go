package deanon

import (
	"context"
	"regexp"
	"strings"

	"github.com/nao1215/onionscan/internal/model"
)

// CloudAnalyzer detects references to cloud services that could
// reveal the infrastructure behind a hidden service.
//
// Cloud service exposure can deanonymize because:
//   - Cloud URLs may resolve to specific accounts
//   - Cloud service identifiers can be traced
//   - Region-specific endpoints reveal geographic location
//   - Cloud-specific headers reveal infrastructure
type CloudAnalyzer struct {
	// patterns contains compiled regex patterns for detection
	patterns []*cloudPattern
}

// cloudPattern holds a pattern and its metadata.
type cloudPattern struct {
	name        string
	description string
	severity    model.Severity
	pattern     *regexp.Regexp
	category    string // "aws", "gcp", "azure", "cloudflare", "cdn", "other"
}

// NewCloudAnalyzer creates a new CloudAnalyzer.
func NewCloudAnalyzer() *CloudAnalyzer {
	return &CloudAnalyzer{
		patterns: []*cloudPattern{
			// AWS
			{
				name:        "aws_s3_bucket",
				description: "AWS S3 bucket URL detected. May reveal AWS account or region.",
				severity:    model.SeverityHigh,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?(?:([a-z0-9][a-z0-9.-]+)\.s3[.-](?:([a-z0-9-]+)\.)?amazonaws\.com|s3[.-](?:([a-z0-9-]+)\.)?amazonaws\.com/([a-z0-9][a-z0-9.-]+))`),
				category:    "aws",
			},
			{
				name:        "aws_cloudfront",
				description: "AWS CloudFront distribution detected. May reveal AWS account.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9]+\.cloudfront\.net`),
				category:    "aws",
			},
			{
				name:        "aws_api_gateway",
				description: "AWS API Gateway endpoint detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com`),
				category:    "aws",
			},
			{
				name:        "aws_lambda",
				description: "AWS Lambda function URL detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws`),
				category:    "aws",
			},
			{
				name:        "aws_ec2",
				description: "AWS EC2 instance identifier or endpoint detected.",
				severity:    model.SeverityHigh,
				pattern:     regexp.MustCompile(`(?i)ec2-[0-9-]+\.[a-z0-9-]+\.compute\.amazonaws\.com|i-[a-f0-9]{8,17}`),
				category:    "aws",
			},
			{
				name:        "aws_elb",
				description: "AWS Elastic Load Balancer detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+\.[a-z0-9-]+\.elb\.amazonaws\.com`),
				category:    "aws",
			},
			{
				name:        "aws_cognito",
				description: "AWS Cognito endpoint detected. May contain user pool ID.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)cognito-idp\.[a-z0-9-]+\.amazonaws\.com|[a-z0-9-]+\.auth\.[a-z0-9-]+\.amazoncognito\.com`),
				category:    "aws",
			},

			// Google Cloud Platform
			{
				name:        "gcp_storage",
				description: "Google Cloud Storage bucket detected.",
				severity:    model.SeverityHigh,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?storage\.googleapis\.com/[a-z0-9][a-z0-9._-]+|(?:https?://)?[a-z0-9][a-z0-9._-]+\.storage\.googleapis\.com`),
				category:    "gcp",
			},
			{
				name:        "gcp_firebase",
				description: "Firebase hosting or database detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+\.firebaseapp\.com|(?:https?://)?[a-z0-9-]+\.firebaseio\.com|(?:https?://)?[a-z0-9-]+\.web\.app`),
				category:    "gcp",
			},
			{
				name:        "gcp_cloud_run",
				description: "Google Cloud Run service detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+-[a-z0-9]+\.run\.app`),
				category:    "gcp",
			},
			{
				name:        "gcp_cloud_functions",
				description: "Google Cloud Functions endpoint detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+-[a-z0-9]+\.cloudfunctions\.net`),
				category:    "gcp",
			},
			{
				name:        "gcp_appengine",
				description: "Google App Engine application detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+\.appspot\.com`),
				category:    "gcp",
			},

			// Microsoft Azure
			{
				name:        "azure_blob",
				description: "Azure Blob Storage detected.",
				severity:    model.SeverityHigh,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9]+\.blob\.core\.windows\.net`),
				category:    "azure",
			},
			{
				name:        "azure_websites",
				description: "Azure Web Apps detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+\.azurewebsites\.net`),
				category:    "azure",
			},
			{
				name:        "azure_functions",
				description: "Azure Functions endpoint detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+\.azurestaticapps\.net`),
				category:    "azure",
			},
			{
				name:        "azure_cdn",
				description: "Azure CDN endpoint detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+\.azureedge\.net`),
				category:    "azure",
			},

			// Cloudflare
			{
				name:        "cloudflare_workers",
				description: "Cloudflare Workers detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+\.workers\.dev`),
				category:    "cloudflare",
			},
			{
				name:        "cloudflare_pages",
				description: "Cloudflare Pages detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+\.pages\.dev`),
				category:    "cloudflare",
			},
			{
				name:        "cloudflare_r2",
				description: "Cloudflare R2 storage detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+\.r2\.dev`),
				category:    "cloudflare",
			},

			// Other CDNs
			{
				name:        "fastly_cdn",
				description: "Fastly CDN detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+\.fastly\.net|(?:https?://)?[a-z0-9-]+\.fastlylb\.net`),
				category:    "cdn",
			},
			{
				name:        "akamai_cdn",
				description: "Akamai CDN detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+\.akamaized\.net|(?:https?://)?[a-z0-9-]+\.akamaihd\.net`),
				category:    "cdn",
			},
			{
				name:        "bunny_cdn",
				description: "Bunny CDN detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+\.b-cdn\.net`),
				category:    "cdn",
			},

			// Other cloud services
			{
				name:        "digitalocean_spaces",
				description: "DigitalOcean Spaces detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+\.[a-z0-9]+\.digitaloceanspaces\.com`),
				category:    "other",
			},
			{
				name:        "digitalocean_app",
				description: "DigitalOcean App Platform detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+\.ondigitalocean\.app`),
				category:    "other",
			},
			{
				name:        "heroku",
				description: "Heroku application detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+\.herokuapp\.com`),
				category:    "other",
			},
			{
				name:        "vercel",
				description: "Vercel deployment detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+\.vercel\.app`),
				category:    "other",
			},
			{
				name:        "netlify",
				description: "Netlify deployment detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+\.netlify\.app|(?:https?://)?[a-z0-9-]+\.netlify\.com`),
				category:    "other",
			},
			{
				name:        "render",
				description: "Render deployment detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+\.onrender\.com`),
				category:    "other",
			},
			{
				name:        "railway",
				description: "Railway deployment detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+\.up\.railway\.app`),
				category:    "other",
			},
			{
				name:        "fly_io",
				description: "Fly.io deployment detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:https?://)?[a-z0-9-]+\.fly\.dev`),
				category:    "other",
			},
		},
	}
}

// Name returns the analyzer name.
func (a *CloudAnalyzer) Name() string {
	return "cloud"
}

// Category returns the analyzer category.
func (a *CloudAnalyzer) Category() string {
	return CategoryCorrelation
}

// Analyze searches for cloud service references in crawled content.
func (a *CloudAnalyzer) Analyze(ctx context.Context, data *AnalysisData) ([]model.Finding, error) {
	findings := make([]model.Finding, 0)
	foundPatterns := make(map[string]bool) // Deduplicate findings

	for _, page := range data.Pages {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Search in page content
		contentFindings := a.searchContent(page.Snapshot, page.URL)
		for _, f := range contentFindings {
			key := f.Type + "|" + f.Value
			if !foundPatterns[key] {
				foundPatterns[key] = true
				findings = append(findings, f)
			}
		}

		// Check headers for cloud-related information
		headerFindings := a.checkHeaders(page.Headers, page.URL)
		for _, f := range headerFindings {
			key := f.Type + "|" + f.Value
			if !foundPatterns[key] {
				foundPatterns[key] = true
				findings = append(findings, f)
			}
		}
	}

	return findings, nil
}

// searchContent searches for cloud service patterns in content.
func (a *CloudAnalyzer) searchContent(content, location string) []model.Finding {
	findings := make([]model.Finding, 0)

	for _, p := range a.patterns {
		if matches := p.pattern.FindAllString(content, 5); len(matches) > 0 {
			// Use first match as the value
			value := matches[0]

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

// checkHeaders looks for cloud-related information in HTTP headers.
func (a *CloudAnalyzer) checkHeaders(headers map[string][]string, location string) []model.Finding {
	findings := make([]model.Finding, 0)

	for headerName, headerValues := range headers {
		lowerName := strings.ToLower(headerName)
		headerValue := ""
		if len(headerValues) > 0 {
			headerValue = headerValues[0]
		}

		// Check for Cloudflare headers
		if strings.Contains(lowerName, "cf-ray") {
			findings = append(findings, model.Finding{
				Type:         "cloudflare_header",
				Title:        "Cloudflare Ray ID Detected",
				Description:  "Site is behind Cloudflare. The Ray ID can help identify the data center.",
				Severity:     model.SeverityMedium,
				SeverityText: model.SeverityMedium.String(),
				Value:        headerName + ": " + headerValue,
				Location:     location,
			})
		}

		// Check for AWS headers
		if strings.Contains(lowerName, "x-amz-") || strings.Contains(lowerName, "x-amzn-") {
			findings = append(findings, model.Finding{
				Type:         "aws_header",
				Title:        "AWS Header Detected",
				Description:  "AWS-specific header found. Service is likely hosted on AWS.",
				Severity:     model.SeverityMedium,
				SeverityText: model.SeverityMedium.String(),
				Value:        headerName + ": " + a.truncateValue(headerValue, 50),
				Location:     location,
			})
		}

		// Check for Azure headers
		if strings.Contains(lowerName, "x-azure-") || strings.Contains(lowerName, "x-ms-") {
			findings = append(findings, model.Finding{
				Type:         "azure_header",
				Title:        "Azure Header Detected",
				Description:  "Azure-specific header found. Service is likely hosted on Azure.",
				Severity:     model.SeverityMedium,
				SeverityText: model.SeverityMedium.String(),
				Value:        headerName + ": " + a.truncateValue(headerValue, 50),
				Location:     location,
			})
		}

		// Check for GCP headers
		if strings.Contains(lowerName, "x-goog-") || strings.Contains(lowerName, "x-guploader-") {
			findings = append(findings, model.Finding{
				Type:         "gcp_header",
				Title:        "Google Cloud Header Detected",
				Description:  "GCP-specific header found. Service is likely hosted on Google Cloud.",
				Severity:     model.SeverityMedium,
				SeverityText: model.SeverityMedium.String(),
				Value:        headerName + ": " + a.truncateValue(headerValue, 50),
				Location:     location,
			})
		}

		// Check Server header for cloud indicators
		if lowerName == "server" {
			lowerValue := strings.ToLower(headerValue)
			if strings.Contains(lowerValue, "cloudflare") {
				findings = append(findings, model.Finding{
					Type:         "cloudflare_server",
					Title:        "Cloudflare Server Detected",
					Description:  "Server header indicates Cloudflare.",
					Severity:     model.SeverityMedium,
					SeverityText: model.SeverityMedium.String(),
					Value:        headerValue,
					Location:     location,
				})
			}
			if strings.Contains(lowerValue, "awselb") || strings.Contains(lowerValue, "amazonec2") {
				findings = append(findings, model.Finding{
					Type:         "aws_server",
					Title:        "AWS Server Detected",
					Description:  "Server header indicates AWS infrastructure.",
					Severity:     model.SeverityMedium,
					SeverityText: model.SeverityMedium.String(),
					Value:        headerValue,
					Location:     location,
				})
			}
		}
	}

	return findings
}

// truncateValue truncates a value to the specified length.
func (a *CloudAnalyzer) truncateValue(value string, maxLen int) string {
	if len(value) > maxLen {
		return value[:maxLen] + "..."
	}
	return value
}

// titleForPattern returns a human-readable title for a pattern type.
func (a *CloudAnalyzer) titleForPattern(patternName string) string {
	titles := map[string]string{
		"aws_s3_bucket":       "AWS S3 Bucket Detected",
		"aws_cloudfront":      "AWS CloudFront Distribution Detected",
		"aws_api_gateway":     "AWS API Gateway Detected",
		"aws_lambda":          "AWS Lambda Function URL Detected",
		"aws_ec2":             "AWS EC2 Instance Detected",
		"aws_elb":             "AWS Elastic Load Balancer Detected",
		"aws_cognito":         "AWS Cognito Endpoint Detected",
		"gcp_storage":         "Google Cloud Storage Detected",
		"gcp_firebase":        "Firebase Hosting/Database Detected",
		"gcp_cloud_run":       "Google Cloud Run Detected",
		"gcp_cloud_functions": "Google Cloud Functions Detected",
		"gcp_appengine":       "Google App Engine Detected",
		"azure_blob":          "Azure Blob Storage Detected",
		"azure_websites":      "Azure Web Apps Detected",
		"azure_functions":     "Azure Functions Detected",
		"azure_cdn":           "Azure CDN Detected",
		"cloudflare_workers":  "Cloudflare Workers Detected",
		"cloudflare_pages":    "Cloudflare Pages Detected",
		"cloudflare_r2":       "Cloudflare R2 Storage Detected",
		"fastly_cdn":          "Fastly CDN Detected",
		"akamai_cdn":          "Akamai CDN Detected",
		"bunny_cdn":           "Bunny CDN Detected",
		"digitalocean_spaces": "DigitalOcean Spaces Detected",
		"digitalocean_app":    "DigitalOcean App Platform Detected",
		"heroku":              "Heroku Application Detected",
		"vercel":              "Vercel Deployment Detected",
		"netlify":             "Netlify Deployment Detected",
		"render":              "Render Deployment Detected",
		"railway":             "Railway Deployment Detected",
		"fly_io":              "Fly.io Deployment Detected",
	}

	if title, ok := titles[patternName]; ok {
		return title
	}
	return "Cloud Service Detected"
}

// Ensure CloudAnalyzer implements CheckAnalyzer.
var _ CheckAnalyzer = (*CloudAnalyzer)(nil)
