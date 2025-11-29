package deanon

import (
	"context"
	"regexp"
	"strings"

	"github.com/nao1215/onionscan/internal/model"
)

// APILeakAnalyzer detects exposed API documentation, internal endpoints,
// and development artifacts that could reveal information about the backend
// infrastructure or provide unauthorized access.
//
// This analyzer checks for:
//   - Swagger/OpenAPI documentation endpoints
//   - GraphQL introspection endpoints
//   - Debug/admin endpoints
//   - Development environment indicators
//   - Internal API patterns
type APILeakAnalyzer struct {
	// patterns contains compiled regex patterns for detection
	patterns []*apiLeakPattern
}

// apiLeakPattern holds a pattern and its metadata.
type apiLeakPattern struct {
	name        string
	description string
	severity    model.Severity
	pattern     *regexp.Regexp
	category    string // "documentation", "endpoint", "debug", "config"
}

// NewAPILeakAnalyzer creates a new APILeakAnalyzer.
func NewAPILeakAnalyzer() *APILeakAnalyzer {
	return &APILeakAnalyzer{
		patterns: []*apiLeakPattern{
			// Swagger/OpenAPI Documentation
			{
				name:        "swagger_ui",
				description: "Swagger UI was found. This exposes the complete API structure and available endpoints.",
				severity:    model.SeverityHigh,
				pattern:     regexp.MustCompile(`(?i)(?:swagger-ui|swaggerui)[^"']*\.(?:js|css|html)|swagger-ui-bundle`),
				category:    "documentation",
			},
			{
				name:        "swagger_json",
				description: "Swagger/OpenAPI JSON specification was found. This reveals all API endpoints and data models.",
				severity:    model.SeverityHigh,
				pattern:     regexp.MustCompile(`(?i)(?:swagger|openapi)\.(?:json|yaml)|/api-docs(?:/|$)|/v\d+/api-docs`),
				category:    "documentation",
			},
			{
				name:        "openapi_spec",
				description: "OpenAPI specification detected. This documents the API structure.",
				severity:    model.SeverityHigh,
				pattern:     regexp.MustCompile(`(?i)"openapi"\s*:\s*"[23]\.\d+\.\d+"|"swagger"\s*:\s*"2\.0"`),
				category:    "documentation",
			},

			// GraphQL
			{
				name:        "graphql_endpoint",
				description: "GraphQL endpoint detected. May allow introspection queries revealing the schema.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)/graphql(?:/|$|\?)|graphql-playground|graphiql`),
				category:    "endpoint",
			},
			{
				name:        "graphql_introspection",
				description: "GraphQL introspection appears to be enabled. This exposes the entire schema.",
				severity:    model.SeverityHigh,
				pattern:     regexp.MustCompile(`(?i)__schema|__type|introspectionquery`),
				category:    "documentation",
			},

			// API Documentation Tools
			{
				name:        "redoc",
				description: "ReDoc API documentation tool detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)redoc\.standalone|redoc-container`),
				category:    "documentation",
			},
			{
				name:        "postman_collection",
				description: "Postman collection reference found. May contain API credentials or internal endpoints.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)postman\.com/collections|\.postman_collection\.json`),
				category:    "documentation",
			},

			// Debug/Admin Endpoints
			{
				name:        "debug_endpoint",
				description: "Debug endpoint detected. May expose sensitive internal information.",
				severity:    model.SeverityHigh,
				pattern:     regexp.MustCompile(`(?i)/debug(?:/|$)|/__debug__|/debug/pprof|/debug/vars`),
				category:    "debug",
			},
			{
				name:        "admin_api",
				description: "Admin API endpoint detected. May provide elevated access.",
				severity:    model.SeverityHigh,
				pattern:     regexp.MustCompile(`(?i)/admin/api|/api/admin|/internal/api|/_internal/`),
				category:    "endpoint",
			},
			{
				name:        "health_check",
				description: "Health check endpoint exposed. May reveal infrastructure details.",
				severity:    model.SeverityLow,
				pattern:     regexp.MustCompile(`(?i)/health(?:check)?(?:/|$)|/ready(?:/|$)|/live(?:/|$)|/status(?:/|$)`),
				category:    "endpoint",
			},
			{
				name:        "metrics_endpoint",
				description: "Metrics endpoint detected (Prometheus/StatsD). Exposes operational data.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)/metrics(?:/|$)|/prometheus|# HELP .* # TYPE`),
				category:    "debug",
			},

			// Development Artifacts
			{
				name:        "env_file",
				description: "Environment file reference found. May contain secrets.",
				severity:    model.SeverityCritical,
				pattern:     regexp.MustCompile(`(?i)\.env(?:\.local|\.development|\.production)?(?:$|[^a-z])|dotenv`),
				category:    "config",
			},
			{
				name:        "config_exposure",
				description: "Configuration file exposure detected.",
				severity:    model.SeverityHigh,
				pattern:     regexp.MustCompile(`(?i)config\.(?:json|yaml|yml|toml)|settings\.py|application\.properties`),
				category:    "config",
			},
			{
				name:        "development_mode",
				description: "Development mode indicators found. Service may have reduced security.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)(?:development|debug)\s*(?:mode|=\s*true)|NODE_ENV.*development|FLASK_DEBUG.*1`),
				category:    "debug",
			},

			// Internal API Patterns
			{
				name:        "internal_api_version",
				description: "Internal API version detected. May indicate non-public endpoints.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)/api/v\d+/internal|/internal/v\d+|/_private/`),
				category:    "endpoint",
			},
			{
				name:        "rpc_endpoint",
				description: "RPC endpoint detected (gRPC/JSON-RPC).",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)/rpc(?:/|$)|grpc-web|json-rpc|jsonrpc`),
				category:    "endpoint",
			},

			// Framework-specific endpoints
			{
				name:        "django_debug",
				description: "Django debug toolbar or settings detected.",
				severity:    model.SeverityHigh,
				pattern:     regexp.MustCompile(`(?i)__debug__/|django-debug-toolbar|DEBUG\s*=\s*True`),
				category:    "debug",
			},
			{
				name:        "flask_debug",
				description: "Flask debugger detected. May allow code execution.",
				severity:    model.SeverityCritical,
				pattern:     regexp.MustCompile(`(?i)werkzeug.*debugger|Debugger PIN|The debugger caught an exception`),
				category:    "debug",
			},
			{
				name:        "rails_routes",
				description: "Rails routes or debug page detected.",
				severity:    model.SeverityMedium,
				pattern:     regexp.MustCompile(`(?i)rails/info/routes|action_dispatch|ActiveRecord`),
				category:    "debug",
			},
			{
				name:        "laravel_debug",
				description: "Laravel debug mode detected. May expose sensitive data.",
				severity:    model.SeverityHigh,
				pattern:     regexp.MustCompile(`(?i)laravel.*exception|ignition-error|APP_DEBUG.*true`),
				category:    "debug",
			},

			// API Key/Token patterns in responses
			{
				name:        "api_key_exposure",
				description: "API key appears to be exposed in response.",
				severity:    model.SeverityHigh,
				pattern:     regexp.MustCompile(`(?i)"api[_-]?key"\s*:\s*"[a-zA-Z0-9_-]{20,}"`),
				category:    "config",
			},
			{
				name:        "bearer_token_exposure",
				description: "Bearer token appears to be exposed.",
				severity:    model.SeverityCritical,
				pattern:     regexp.MustCompile(`(?i)"(?:access_?token|bearer|jwt)"\s*:\s*"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"`),
				category:    "config",
			},

			// Database connection strings
			{
				name:        "database_url",
				description: "Database connection URL detected. May contain credentials.",
				severity:    model.SeverityCritical,
				pattern:     regexp.MustCompile(`(?i)(?:postgres|mysql|mongodb|redis)://[^@]+@[^/]+/\w+`),
				category:    "config",
			},
		},
	}
}

// Name returns the analyzer name.
func (a *APILeakAnalyzer) Name() string {
	return "apileak"
}

// Category returns the analyzer category.
func (a *APILeakAnalyzer) Category() string {
	return "correlation"
}

// Analyze searches for API leaks in crawled content.
func (a *APILeakAnalyzer) Analyze(ctx context.Context, data *AnalysisData) ([]model.Finding, error) {
	findings := make([]model.Finding, 0)
	foundPatterns := make(map[string]bool) // Deduplicate findings

	for _, page := range data.Pages {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Check URL for API patterns
		urlFindings := a.checkURL(page.URL)
		for _, f := range urlFindings {
			key := f.Type + "|" + f.Value
			if !foundPatterns[key] {
				foundPatterns[key] = true
				findings = append(findings, f)
			}
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

		// Search in headers
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

// checkURL looks for API-related patterns in URLs.
func (a *APILeakAnalyzer) checkURL(url string) []model.Finding {
	findings := make([]model.Finding, 0)

	for _, p := range a.patterns {
		// Only check URL-based patterns (endpoint, documentation, debug)
		if p.category != "endpoint" && p.category != "documentation" && p.category != "debug" {
			continue
		}
		if p.pattern.MatchString(url) {
			findings = append(findings, model.Finding{
				Type:         p.name,
				Title:        a.titleForPattern(p.name),
				Description:  p.description,
				Severity:     p.severity,
				SeverityText: p.severity.String(),
				Value:        a.sanitizeValue(url, p.name),
				Location:     url,
			})
		}
	}

	return findings
}

// searchContent searches for API leak patterns in content.
func (a *APILeakAnalyzer) searchContent(content, location string) []model.Finding {
	findings := make([]model.Finding, 0)

	for _, p := range a.patterns {
		if matches := p.pattern.FindAllString(content, 3); len(matches) > 0 {
			// Sanitize the match value
			value := a.sanitizeValue(matches[0], p.name)

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

// checkHeaders looks for API-related information in HTTP headers.
func (a *APILeakAnalyzer) checkHeaders(headers map[string][]string, location string) []model.Finding {
	findings := make([]model.Finding, 0)

	for headerName, headerValues := range headers {
		lowerName := strings.ToLower(headerName)
		headerValue := ""
		if len(headerValues) > 0 {
			headerValue = headerValues[0]
		}

		// Check for API version headers
		if strings.Contains(lowerName, "api-version") || strings.Contains(lowerName, "x-api-version") {
			findings = append(findings, model.Finding{
				Type:         "api_version_header",
				Title:        "API Version Header Exposed",
				Description:  "API version information exposed in headers.",
				Severity:     model.SeverityLow,
				SeverityText: model.SeverityLow.String(),
				Value:        headerName + ": " + headerValue,
				Location:     location,
			})
		}

		// Check for debug headers
		if strings.Contains(lowerName, "debug") || strings.Contains(lowerName, "x-debug") {
			findings = append(findings, model.Finding{
				Type:         "debug_header",
				Title:        "Debug Header Detected",
				Description:  "Debug-related header found. May indicate development mode.",
				Severity:     model.SeverityMedium,
				SeverityText: model.SeverityMedium.String(),
				Value:        headerName + ": " + a.truncateValue(headerValue, 50),
				Location:     location,
			})
		}
	}

	return findings
}

// sanitizeValue returns a safe representation of the matched value.
func (a *APILeakAnalyzer) sanitizeValue(value, patternName string) string {
	// For sensitive patterns, redact credentials
	if strings.Contains(patternName, "token") || strings.Contains(patternName, "key") {
		if len(value) > 30 {
			return value[:30] + "...[REDACTED]"
		}
	}

	// For database URLs, redact credentials
	if patternName == "database_url" {
		// Replace password portion
		re := regexp.MustCompile(`://([^:]+):([^@]+)@`)
		value = re.ReplaceAllString(value, "://$1:[REDACTED]@")
	}

	return a.truncateValue(value, 100)
}

// truncateValue truncates a value to the specified length.
func (a *APILeakAnalyzer) truncateValue(value string, maxLen int) string {
	if len(value) > maxLen {
		return value[:maxLen] + "..."
	}
	return value
}

// titleForPattern returns a human-readable title for a pattern type.
func (a *APILeakAnalyzer) titleForPattern(patternName string) string {
	titles := map[string]string{
		"swagger_ui":            "Swagger UI Exposed",
		"swagger_json":          "Swagger/OpenAPI Specification Found",
		"openapi_spec":          "OpenAPI Specification Detected",
		"graphql_endpoint":      "GraphQL Endpoint Detected",
		"graphql_introspection": "GraphQL Introspection Enabled",
		"redoc":                 "ReDoc Documentation Exposed",
		"postman_collection":    "Postman Collection Reference Found",
		"debug_endpoint":        "Debug Endpoint Exposed",
		"admin_api":             "Admin API Endpoint Detected",
		"health_check":          "Health Check Endpoint Exposed",
		"metrics_endpoint":      "Metrics Endpoint Exposed",
		"env_file":              "Environment File Reference Found",
		"config_exposure":       "Configuration File Exposed",
		"development_mode":      "Development Mode Detected",
		"internal_api_version":  "Internal API Version Detected",
		"rpc_endpoint":          "RPC Endpoint Detected",
		"django_debug":          "Django Debug Mode Detected",
		"flask_debug":           "Flask Debugger Detected",
		"rails_routes":          "Rails Debug Information Exposed",
		"laravel_debug":         "Laravel Debug Mode Detected",
		"api_key_exposure":      "API Key Exposed in Response",
		"bearer_token_exposure": "Bearer Token Exposed",
		"database_url":          "Database Connection URL Exposed",
	}

	if title, ok := titles[patternName]; ok {
		return title
	}
	return "API Leak Detected"
}

// Ensure APILeakAnalyzer implements CheckAnalyzer.
var _ CheckAnalyzer = (*APILeakAnalyzer)(nil)
