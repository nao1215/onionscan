package model

import (
	"crypto/x509"
	"time"
)

// OnionScanReport is the main scan result structure.
// It contains all information collected during a scan of a hidden service.
//
// Design decision: We use a single large struct rather than many small ones
// to simplify serialization and database storage. The AnonymityReport sub-struct
// groups related anonymity findings for easier access.
type OnionScanReport struct {
	// === Basic Information ===

	// HiddenService is the scanned .onion address.
	HiddenService string `json:"hidden_service"`

	// OnionVersion is the onion address version (2 or 3).
	// V2 is deprecated since 2021; new scans should only have 3.
	OnionVersion int `json:"onion_version"`

	// DateScanned is the timestamp when the scan was performed.
	DateScanned time.Time `json:"date_scanned"`

	// === Protocol Detection Flags ===
	// These flags indicate which services were detected on the hidden service.
	// True means the service responded on the expected port.

	// WebDetected is true if HTTP service was found on port 80.
	WebDetected bool `json:"web_detected"`

	// TLSDetected is true if HTTPS service was found on port 443.
	TLSDetected bool `json:"tls_detected"`

	// SSHDetected is true if SSH service was found on port 22.
	SSHDetected bool `json:"ssh_detected"`

	// FTPDetected is true if FTP service was found on port 21.
	FTPDetected bool `json:"ftp_detected"`

	// SMTPDetected is true if SMTP service was found on port 25.
	SMTPDetected bool `json:"smtp_detected"`

	// MongoDBDetected is true if MongoDB was found on port 27017.
	MongoDBDetected bool `json:"mongodb_detected"` //nolint:tagliatelle // MongoDB is product name

	// RedisDetected is true if Redis was found on port 6379.
	RedisDetected bool `json:"redis_detected"`

	// PostgreSQLDetected is true if PostgreSQL was found on port 5432.
	PostgreSQLDetected bool `json:"postgresql_detected"` //nolint:tagliatelle // PostgreSQL is product name

	// MySQLDetected is true if MySQL was found on port 3306.
	MySQLDetected bool `json:"mysql_detected"` //nolint:tagliatelle // MySQL is product name

	// BitcoinDetected is true if Bitcoin P2P was found on port 8333.
	BitcoinDetected bool `json:"bitcoin_detected"`

	// === SSH Data ===

	// SSHKey is the SSH host key fingerprint (SHA256 format).
	SSHKey string `json:"ssh_key,omitempty"`

	// SSHBanner is the SSH version banner.
	SSHBanner string `json:"ssh_banner,omitempty"`

	// SSHKeyType is the key algorithm (ed25519, rsa, ecdsa).
	SSHKeyType string `json:"ssh_key_type,omitempty"`

	// === FTP Data ===

	// FTPBanner is the FTP server banner.
	FTPBanner string `json:"ftp_banner,omitempty"`

	// FTPFingerprint is a fingerprint of the FTP server.
	FTPFingerprint string `json:"ftp_fingerprint,omitempty"`

	// === SMTP Data ===

	// SMTPBanner is the SMTP server banner.
	SMTPBanner string `json:"smtp_banner,omitempty"`

	// SMTPFingerprint is a fingerprint of the SMTP server.
	SMTPFingerprint string `json:"smtp_fingerprint,omitempty"`

	// === TLS Data ===

	// Certificates contains the TLS certificate chain.
	// The first certificate is the server certificate.
	Certificates []*x509.Certificate `json:"-"` // Excluded from JSON (serialize separately)

	// CertificateInfo contains serializable certificate information.
	CertificateInfo []CertificateInfo `json:"certificates,omitempty"` //nolint:tagliatelle // shorter name preferred

	// TLSVersion is the negotiated TLS version.
	TLSVersion uint16 `json:"tls_version,omitempty"`

	// CipherSuite is the negotiated cipher suite.
	CipherSuite uint16 `json:"cipher_suite,omitempty"`

	// === Bitcoin Data ===

	// BitcoinServices contains Bitcoin network information.
	BitcoinServices *BitcoinService `json:"bitcoin_services,omitempty"`

	// === Crawl Data ===

	// Crawls maps URLs to their HTTP status codes.
	// Used to track which pages were successfully crawled.
	Crawls map[string]int `json:"crawls,omitempty"`

	// PageCache stores crawled pages by URL.
	// Used for deanonymization analysis.
	PageCache map[string]*Page `json:"-"` // Excluded from JSON due to size

	// CrawledPages contains all pages discovered during crawling.
	// Used for deanonymization analysis.
	CrawledPages []*Page `json:"-"` // Excluded from JSON due to size

	// ServerVersion is the web server version from the Server header.
	ServerVersion string `json:"server_version,omitempty"`

	// TLSCertificate contains simplified TLS certificate information.
	TLSCertificate *CertInfo `json:"tls_certificate,omitempty"`

	// === PGP Data ===

	// PGPKeys contains PGP public keys found on the service.
	PGPKeys []PGPKey `json:"pgp_keys,omitempty"`

	// === Sub-Reports ===

	// AnonymityReport contains detailed anonymity findings.
	AnonymityReport *AnonymityReport `json:"anonymity_report,omitempty"`

	// SimpleReport contains the summarized findings for human-readable output.
	SimpleReport *SimpleReport `json:"simple_report,omitempty"`

	// === Scan State ===

	// TimedOut is true if the scan was terminated due to timeout.
	TimedOut bool `json:"timed_out"`

	// PerformedScans lists the scan types that were actually performed.
	PerformedScans []string `json:"performed_scans,omitempty"`

	// Error contains any error that occurred during scanning.
	// Only set if the scan failed or partially failed.
	Error error `json:"-"` // Excluded from JSON

	// ErrorMessage is the string representation of Error for serialization.
	ErrorMessage string `json:"error,omitempty"` //nolint:tagliatelle // error is conventional
}

// CertificateInfo contains serializable TLS certificate information.
// We extract this from x509.Certificate because that type doesn't serialize well.
type CertificateInfo struct {
	// Subject is the certificate subject (typically the domain name).
	Subject string `json:"subject"`

	// Issuer is the certificate issuer.
	Issuer string `json:"issuer"`

	// SerialNumber is the certificate serial number as hex string.
	SerialNumber string `json:"serial_number"`

	// NotBefore is when the certificate becomes valid.
	NotBefore time.Time `json:"not_before"`

	// NotAfter is when the certificate expires.
	NotAfter time.Time `json:"not_after"`

	// SANs contains Subject Alternative Names.
	SANs []string `json:"sans,omitempty"` //nolint:tagliatelle // SANs is standard acronym

	// IsCA indicates if this is a CA certificate.
	IsCA bool `json:"is_ca"`
}

// BitcoinService contains Bitcoin node information.
type BitcoinService struct {
	// UserAgent is the Bitcoin client user agent string.
	UserAgent string `json:"user_agent"`

	// ProtocolVersion is the Bitcoin protocol version.
	ProtocolVersion int `json:"protocol_version"`

	// PeerAddresses contains onion addresses of connected peers.
	// V3 onion addresses are 56 characters.
	PeerAddresses []string `json:"peer_addresses,omitempty"`
}

// CertInfo contains simplified TLS certificate information for display.
// This is a more compact representation than CertificateInfo.
type CertInfo struct {
	// Subject is the certificate subject.
	Subject string `json:"subject"`

	// Issuer is the certificate issuer.
	Issuer string `json:"issuer"`

	// NotBefore is when the certificate becomes valid (RFC3339 format).
	NotBefore string `json:"not_before"`

	// NotAfter is when the certificate expires (RFC3339 format).
	NotAfter string `json:"not_after"`

	// CommonName is the certificate's common name.
	CommonName string `json:"common_name,omitempty"`

	// SANs contains Subject Alternative Names.
	SANs []string `json:"sans,omitempty"` //nolint:tagliatelle // SANs is standard acronym
}

// PGPKey contains extracted PGP public key information.
type PGPKey struct {
	// Fingerprint is the key fingerprint.
	Fingerprint string `json:"fingerprint"`

	// Identity is the user ID associated with the key.
	Identity string `json:"identity"`

	// ArmoredKey is the ASCII-armored public key.
	ArmoredKey string `json:"armored_key,omitempty"`

	// CreationTime is when the key was created.
	CreationTime time.Time `json:"creation_time,omitempty"`
}

// NewOnionScanReport creates a new report for the given hidden service.
func NewOnionScanReport(hiddenService string) *OnionScanReport {
	return &OnionScanReport{
		HiddenService:   hiddenService,
		OnionVersion:    3, // Default to v3; v2 is deprecated
		DateScanned:     time.Now(),
		Crawls:          make(map[string]int),
		PageCache:       make(map[string]*Page),
		AnonymityReport: NewAnonymityReport(),
	}
}

// AddPage adds a crawled page to the report.
func (r *OnionScanReport) AddPage(url string, page *Page) {
	r.Crawls[url] = page.StatusCode
	r.PageCache[url] = page
}

// GetPage retrieves a cached page by URL.
// Returns nil if the page was not crawled.
func (r *OnionScanReport) GetPage(url string) *Page {
	return r.PageCache[url]
}

// AddFinding adds a finding to the simple report.
// If the simple report doesn't exist, it initializes one.
//
// Design decision: We store findings in SimpleReport rather than
// a separate findings slice because:
// 1. SimpleReport already has finding aggregation logic
// 2. Avoids duplication of findings data
// 3. Keeps the main report focused on raw data
func (r *OnionScanReport) AddFinding(finding Finding) {
	if r.SimpleReport == nil {
		r.SimpleReport = &SimpleReport{
			HiddenService: r.HiddenService,
			DateScanned:   r.DateScanned,
			Findings:      make([]Finding, 0),
		}
	}

	// Keep page count in sync when SimpleReport is first created via AddFinding.
	if r.SimpleReport.PagesCrawled == 0 {
		if count := len(r.CrawledPages); count > 0 {
			r.SimpleReport.PagesCrawled = count
		} else if count := len(r.Crawls); count > 0 {
			r.SimpleReport.PagesCrawled = count
		}
	}

	// Avoid duplicates based on type and value
	for _, f := range r.SimpleReport.Findings {
		if f.Type == finding.Type && f.Value == finding.Value && f.Location == finding.Location {
			return
		}
	}

	r.SimpleReport.Findings = append(r.SimpleReport.Findings, finding)

	// Update severity counts
	switch finding.Severity {
	case SeverityCritical:
		r.SimpleReport.CriticalCount++
	case SeverityHigh:
		r.SimpleReport.HighCount++
	case SeverityMedium:
		r.SimpleReport.MediumCount++
	case SeverityLow:
		r.SimpleReport.LowCount++
	case SeverityInfo:
		r.SimpleReport.InfoCount++
	}
}
