package protocol

import (
	"context"
	"net/http"

	"github.com/nao1215/onionscan/internal/model"
)

// Scanner defines the interface for protocol-specific scanners.
// Each protocol implementation must provide this interface to be used
// in the scanning pipeline.
//
// Design decision: We use an interface rather than a concrete type because:
//  1. Different protocols require vastly different implementations
//  2. Allows for easy mocking in tests
//  3. Enables protocol plugins in the future
//  4. Pipeline can treat all protocols uniformly
type Scanner interface {
	// Scan performs protocol-specific scanning on the target.
	// It returns a ScanResult containing findings and detected information.
	//
	// The context should be used for cancellation and timeouts.
	// Implementations must respect context cancellation.
	Scan(ctx context.Context, target string) (*ScanResult, error)

	// Protocol returns the protocol name (e.g., "http", "ssh").
	Protocol() string

	// DefaultPort returns the default port for this protocol.
	DefaultPort() int
}

// ScanResult contains the results of a protocol scan.
// It aggregates all findings and extracted information from the scan.
//
// Design decision: We use a generic result type rather than protocol-specific
// results because:
//  1. The pipeline needs a uniform way to collect results
//  2. Common fields like status and timing apply to all protocols
//  3. Protocol-specific data can be stored in the Metadata map
type ScanResult struct {
	// Protocol is the scanned protocol (e.g., "http", "ssh").
	Protocol string

	// Port is the port that was scanned.
	Port int

	// Detected indicates whether the service was detected.
	Detected bool

	// Banner contains any banner or version information returned.
	// For HTTP, this might be the Server header.
	// For SSH, this is the version string.
	Banner string

	// Headers contains HTTP headers if applicable.
	// Only populated for HTTP/HTTPS scans.
	Headers http.Header

	// TLS indicates whether TLS/SSL was detected.
	TLS bool

	// TLSVersion contains the TLS version if TLS was detected.
	TLSVersion string

	// Certificate contains TLS certificate information if available.
	Certificate *CertificateInfo

	// Pages contains crawled pages for HTTP/HTTPS.
	// Only populated when crawling is enabled.
	Pages []*model.Page

	// Findings contains security findings from this scan.
	Findings []Finding

	// Metadata contains protocol-specific additional data.
	// This allows protocols to store custom information without
	// modifying the ScanResult structure.
	Metadata map[string]interface{}
}

// CertificateInfo contains information extracted from a TLS certificate.
// This is used for identifying potential deanonymization vectors.
//
// Design decision: We extract specific fields rather than storing the
// raw certificate because:
//  1. Only certain fields are relevant for anonymity analysis
//  2. Reduces memory usage
//  3. Easier to serialize to JSON
//  4. Avoids exposing cryptographic types in reports
type CertificateInfo struct {
	// Subject is the certificate subject (e.g., CN, O, OU).
	Subject string

	// Issuer is the certificate issuer.
	Issuer string

	// NotBefore is the certificate validity start time.
	NotBefore string

	// NotAfter is the certificate validity end time.
	NotAfter string

	// SerialNumber is the certificate serial number.
	SerialNumber string

	// CommonName is the certificate's common name.
	CommonName string

	// SANs contains Subject Alternative Names (all types).
	// These may leak the operator's other domains.
	SANs []string

	// DNSNames contains Subject Alternative Names (DNS).
	// These may leak the operator's other domains.
	DNSNames []string

	// EmailAddresses contains email addresses from the certificate.
	// These are potential deanonymization vectors.
	EmailAddresses []string

	// IssuingOrganization is the organization that issued the certificate.
	IssuingOrganization string
}

// Finding represents a security finding from a protocol scan.
// It follows the same structure as model.Finding for consistency.
type Finding struct {
	// Type is the finding type identifier for categorization.
	Type string

	// Title is a short description of the finding.
	Title string

	// Description provides detailed information about the finding.
	Description string

	// Severity indicates the risk level.
	Severity model.Severity

	// Value contains the specific value found (e.g., email address).
	Value string

	// Location indicates where the finding was discovered.
	Location string

	// Category groups related findings (e.g., "email", "analytics").
	Category string
}

// NewScanResult creates a new ScanResult with initialized maps.
// This ensures Metadata is never nil, avoiding nil pointer dereferences.
//
// Design decision: We provide a constructor rather than relying on
// zero values because:
//  1. Maps must be initialized before use
//  2. Provides a consistent way to create results
//  3. Can set sensible defaults
func NewScanResult(protocol string, port int) *ScanResult {
	return &ScanResult{
		Protocol: protocol,
		Port:     port,
		Detected: false,
		Headers:  make(http.Header),
		Pages:    make([]*model.Page, 0),
		Findings: make([]Finding, 0),
		Metadata: make(map[string]interface{}),
	}
}

// AddFinding adds a security finding to the scan result.
// This is a convenience method that handles nil slices.
func (r *ScanResult) AddFinding(f Finding) {
	if r.Findings == nil {
		r.Findings = make([]Finding, 0)
	}
	r.Findings = append(r.Findings, f)
}

// SetMetadata sets a metadata value for the given key.
// This is a convenience method that handles nil maps.
func (r *ScanResult) SetMetadata(key string, value interface{}) {
	if r.Metadata == nil {
		r.Metadata = make(map[string]interface{})
	}
	r.Metadata[key] = value
}

// GetMetadata retrieves a metadata value for the given key.
// Returns nil if the key doesn't exist or Metadata is nil.
func (r *ScanResult) GetMetadata(key string) interface{} {
	if r.Metadata == nil {
		return nil
	}
	return r.Metadata[key]
}
