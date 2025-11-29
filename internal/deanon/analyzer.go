package deanon

import (
	"context"
	"net/http"

	"github.com/nao1215/onionscan/internal/model"
	"github.com/nao1215/onionscan/internal/protocol"
)

// Analyzer category constants.
const (
	// CategoryCorrelation is used by analyzers that find correlation vectors.
	CategoryCorrelation = "correlation"
	// CategoryIdentity is used by analyzers that find identity information.
	CategoryIdentity = "identity"
)

// Analyzer coordinates deanonymization checks across multiple analyzers.
// It aggregates findings from different analysis types into a unified report.
//
// Design decision: We use a coordinator pattern rather than running analyzers
// independently because:
//  1. Some analyzers may need results from others (correlation analysis)
//  2. Unified severity assessment across all findings
//  3. Deduplication of similar findings
//  4. Consistent context and cancellation handling
type Analyzer struct {
	// analyzers is the list of registered analyzers to run.
	analyzers []CheckAnalyzer

	// options configures analyzer behavior.
	options AnalyzerOptions
}

// AnalyzerOptions configures the analyzer behavior.
type AnalyzerOptions struct {
	// EnableEXIF enables EXIF metadata extraction from images.
	// This can be slow for pages with many images.
	EnableEXIF bool

	// EnablePDFAnalysis enables PDF metadata extraction.
	EnablePDFAnalysis bool

	// AnalyticsPatterns are additional analytics ID patterns to detect.
	AnalyticsPatterns []string

	// CustomEmailDomains are additional email domains to flag.
	CustomEmailDomains []string
}

// DefaultOptions returns sensible default analyzer options.
func DefaultOptions() AnalyzerOptions {
	return AnalyzerOptions{
		EnableEXIF:        true,
		EnablePDFAnalysis: true,
	}
}

// CheckAnalyzer defines the interface for individual analyzers.
// Each analyzer focuses on a specific type of deanonymization check.
//
// Design decision: We use an interface rather than concrete types because:
//  1. Allows for easy extension with new analyzers
//  2. Enables testing with mock analyzers
//  3. Supports different analyzer implementations for the same check type
type CheckAnalyzer interface {
	// Name returns the analyzer's name for logging and reporting.
	Name() string

	// Category returns the analyzer's category (e.g., "identity", "technical").
	Category() string

	// Analyze runs the analysis on the provided data.
	// It returns findings discovered during analysis.
	Analyze(ctx context.Context, data *AnalysisData) ([]model.Finding, error)
}

// AnalysisData contains all data available for analysis.
// This structure aggregates data from crawling and protocol scanning.
//
// Design decision: We pass all data in a single struct rather than
// multiple parameters because:
//  1. Not all analyzers need all data types
//  2. Adding new data types doesn't change analyzer signatures
//  3. Easier to mock in tests
type AnalysisData struct {
	// HiddenService is the onion address being analyzed.
	HiddenService string

	// Pages contains all crawled pages.
	Pages []*model.Page

	// ProtocolResults contains results from protocol scanners.
	ProtocolResults map[string]*protocol.ScanResult

	// Report is the current scan report (for adding findings).
	Report *model.OnionScanReport
}

// NewAnalyzer creates a new Analyzer with all built-in analyzers registered.
func NewAnalyzer(opts ...func(*AnalyzerOptions)) *Analyzer {
	options := DefaultOptions()
	for _, opt := range opts {
		opt(&options)
	}

	a := &Analyzer{
		options:   options,
		analyzers: make([]CheckAnalyzer, 0),
	}

	// Register built-in analyzers
	// Identity analyzers
	a.Register(NewEmailAnalyzer())
	a.Register(NewSocialAnalyzer())
	if options.EnableEXIF {
		a.Register(NewEXIFAnalyzer())
	}
	if options.EnablePDFAnalysis {
		a.Register(NewPDFAnalyzer())
	}

	// Correlation analyzers
	a.Register(NewAnalyticsAnalyzer())
	a.Register(NewCryptoAnalyzer())
	a.Register(NewExternalLinkAnalyzer())
	a.Register(NewAPILeakAnalyzer())
	a.Register(NewCloudAnalyzer())

	// Technical analyzers
	a.Register(NewServerInfoAnalyzer())

	// Security header analyzers (visitor protection)
	a.Register(NewHeaderAnalyzer())

	// Attack detection analyzers
	a.Register(NewFingerprintAnalyzer())
	a.Register(NewMaliciousAnalyzer())

	// Secrets detection analyzers
	a.Register(NewPrivateKeyAnalyzer())

	return a
}

// HTTPClientSetter is implemented by analyzers that need an HTTP client.
type HTTPClientSetter interface {
	SetHTTPClient(client *http.Client)
}

// SetHTTPClient injects an HTTP client into analyzers that require it (EXIF/PDF).
func (a *Analyzer) SetHTTPClient(client *http.Client) {
	for _, analyzer := range a.analyzers {
		if setter, ok := analyzer.(HTTPClientSetter); ok {
			setter.SetHTTPClient(client)
		}
	}
}

// Register adds an analyzer to the list.
func (a *Analyzer) Register(analyzer CheckAnalyzer) {
	a.analyzers = append(a.analyzers, analyzer)
}

// Analyze runs all registered analyzers and aggregates findings.
func (a *Analyzer) Analyze(ctx context.Context, data *AnalysisData) ([]model.Finding, error) {
	var allFindings []model.Finding

	for _, analyzer := range a.analyzers {
		select {
		case <-ctx.Done():
			return allFindings, ctx.Err()
		default:
		}

		findings, err := analyzer.Analyze(ctx, data)
		if err != nil {
			// Log error but continue with other analyzers
			// We want to collect as many findings as possible
			continue
		}

		allFindings = append(allFindings, findings...)
	}

	// Deduplicate findings
	allFindings = deduplicateFindings(allFindings)

	return allFindings, nil
}

// deduplicateFindings removes duplicate findings based on title and value.
//
// Design decision: We deduplicate by title+value rather than just value because:
//  1. Same value might have different meanings in different contexts
//  2. Multiple analyzers might find the same thing
//  3. We want to keep the most severe instance of each finding
func deduplicateFindings(findings []model.Finding) []model.Finding {
	seen := make(map[string]int) // key -> index in result
	result := make([]model.Finding, 0)

	for _, f := range findings {
		key := f.Title + "|" + f.Value
		if idx, exists := seen[key]; exists {
			// Keep the more severe finding
			if f.Severity > result[idx].Severity {
				result[idx] = f
			}
		} else {
			seen[key] = len(result)
			result = append(result, f)
		}
	}

	return result
}
