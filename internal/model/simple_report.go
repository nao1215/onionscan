package model

import "time"

// SimpleReport is a summarized, human-readable report.
// It extracts key findings from the full scan report for quick review.
//
// Design decision: We create a separate simplified report rather than
// just printing parts of OnionScanReport because:
// 1. It provides a consistent, curated view of the most important findings
// 2. It can be serialized to JSON for tools that want structured but simple output
// 3. It separates presentation concerns from data collection
type SimpleReport struct {
	// HiddenService is the scanned .onion address.
	HiddenService string `json:"hidden_service"`

	// DateScanned is when the scan was performed.
	DateScanned time.Time `json:"date_scanned"`

	// === Severity Summary ===

	// CriticalCount is the number of critical findings.
	CriticalCount int `json:"critical_count"`

	// HighCount is the number of high severity findings.
	HighCount int `json:"high_count"`

	// MediumCount is the number of medium severity findings.
	MediumCount int `json:"medium_count"`

	// LowCount is the number of low severity findings.
	LowCount int `json:"low_count"`

	// InfoCount is the number of informational findings.
	InfoCount int `json:"info_count"`

	// === Services ===

	// DetectedServices lists all detected network services.
	DetectedServices []string `json:"detected_services,omitempty"`

	// === Findings ===

	// Findings contains all categorized findings.
	Findings []Finding `json:"findings,omitempty"`

	// === Page Statistics ===

	// PagesCrawled is the number of pages successfully crawled.
	PagesCrawled int `json:"pages_crawled"`

	// TimedOut indicates if the scan was terminated due to timeout.
	TimedOut bool `json:"timed_out"`

	// Error contains any error message if the scan failed.
	Error string `json:"error,omitempty"`
}

// Finding represents a single finding in the simple report.
type Finding struct {
	// Type is the finding type identifier.
	// This maps to the riskMapping in severity.go.
	Type string `json:"type"`

	// Severity is the risk level.
	Severity Severity `json:"severity"`

	// SeverityText is the human-readable severity.
	SeverityText string `json:"severity_text"`

	// Title is a short description of the finding.
	Title string `json:"title"`

	// Description provides more detail about the finding.
	Description string `json:"description,omitempty"`

	// Impact explains the security implications of this finding.
	// This helps users understand why this finding matters.
	Impact string `json:"impact,omitempty"`

	// Recommendation provides guidance on how to address this finding.
	Recommendation string `json:"recommendation,omitempty"`

	// Value is the specific value found (address, ID, etc.).
	Value string `json:"value,omitempty"`

	// Location is where the finding was discovered.
	Location string `json:"location,omitempty"`
}

// NewSimpleReport creates a new SimpleReport from an OnionScanReport.
// This extracts and summarizes key findings.
func NewSimpleReport(report *OnionScanReport) *SimpleReport {
	simple := &SimpleReport{
		HiddenService: report.HiddenService,
		DateScanned:   report.DateScanned,
		PagesCrawled:  len(report.CrawledPages),
		TimedOut:      report.TimedOut,
	}

	if report.Error != nil {
		simple.Error = report.Error.Error()
	}

	// Collect detected services
	simple.collectDetectedServices(report)

	// Collect findings from anonymity report
	if report.AnonymityReport != nil {
		simple.collectFindings(report.AnonymityReport)
	}

	// Count findings by severity
	simple.countBySeverity()

	return simple
}

// collectDetectedServices extracts the list of detected services.
func (s *SimpleReport) collectDetectedServices(report *OnionScanReport) {
	if report.WebDetected {
		s.DetectedServices = append(s.DetectedServices, "HTTP (80)")
	}
	if report.TLSDetected {
		s.DetectedServices = append(s.DetectedServices, "HTTPS (443)")
	}
	if report.SSHDetected {
		s.DetectedServices = append(s.DetectedServices, "SSH (22)")
	}
	if report.FTPDetected {
		s.DetectedServices = append(s.DetectedServices, "FTP (21)")
	}
	if report.SMTPDetected {
		s.DetectedServices = append(s.DetectedServices, "SMTP (25)")
	}
	if report.MongoDBDetected {
		s.DetectedServices = append(s.DetectedServices, "MongoDB (27017)")
	}
	if report.RedisDetected {
		s.DetectedServices = append(s.DetectedServices, "Redis (6379)")
	}
	if report.PostgreSQLDetected {
		s.DetectedServices = append(s.DetectedServices, "PostgreSQL (5432)")
	}
	if report.MySQLDetected {
		s.DetectedServices = append(s.DetectedServices, "MySQL (3306)")
	}
	if report.BitcoinDetected {
		s.DetectedServices = append(s.DetectedServices, "Bitcoin (8333)")
	}
}

// collectFindings extracts findings from the anonymity report.
func (s *SimpleReport) collectFindings(ar *AnonymityReport) {
	// Critical findings
	if ar.PrivateKeyExposed {
		s.addFinding("private_key_"+ar.PrivateKeyType, "Private Key Exposed",
			"The hidden service private key was found publicly accessible",
			ar.PrivateKeyType, "")
	}
	if ar.HostnameFileExposed {
		s.addFinding("hostname_file", "Hostname File Exposed",
			"The hostname file is publicly accessible", "", "")
	}
	for _, ip := range ar.IPAddresses {
		s.addFinding("clearnet_ip", "Clearnet IP Address Found",
			"A clearnet IP address was found, potentially revealing the server's real location",
			ip, "")
	}

	// High findings
	if ar.ApacheModStatusFound {
		s.addFinding("apache_mod_status", "Apache mod_status Exposed",
			"Apache server-status page is publicly accessible, revealing server information",
			"", "/server-status")
	}
	if ar.NginxStatusFound {
		s.addFinding("nginx_status", "Nginx Status Page Exposed",
			"Nginx status page is publicly accessible", "", "/nginx_status")
	}
	if ar.CloudflareDetected {
		s.addFinding("cloudflare_detected", "Cloudflare Detected",
			"Service is using Cloudflare, which may have access to the real IP",
			ar.CloudflareRayID, "")
	}
	for _, analytics := range ar.AnalyticsIDs {
		title := "Analytics Tracker Detected"
		desc := "Analytics tracker found - requests are sent to third-party servers"
		s.addFinding("google_analytics_"+analytics.Type, title, desc, analytics.ID, "")
	}
	for _, aws := range ar.AWSResources {
		s.addFinding("aws_"+aws.Type, "AWS Resource Detected",
			"AWS resource detected - may be linked to an AWS account",
			aws.Identifier, "")
	}
	for _, domain := range ar.CSPExternalDomains {
		s.addFinding("csp_external_domains", "External Domain in CSP",
			"Content Security Policy references an external domain",
			domain, "")
	}
	for _, endpoint := range ar.APIEndpoints {
		s.addFinding("external_api", "External API Endpoint",
			"JavaScript makes requests to an external API",
			endpoint.URL, endpoint.Context)
	}

	// Medium findings
	for _, email := range ar.EmailAddresses {
		s.addFinding("email_address", "Email Address Found",
			"Email address found in page content", email, "")
	}
	for _, social := range ar.SocialLinks {
		s.addFinding("social_"+social.Platform, "Social Media Link",
			"Social media profile link found", social.Username, social.URL)
	}
	for _, dir := range ar.OpenDirectories {
		s.addFinding("open_directory", "Open Directory",
			"Directory listing is publicly accessible", "", dir)
	}
	if ar.ServerVersion != "" {
		s.addFinding("server_version", "Server Version Exposed",
			"Server header reveals software version", ar.ServerVersion, "")
	}
	if ar.XPoweredBy != "" {
		s.addFinding("x_powered_by", "X-Powered-By Header",
			"X-Powered-By header reveals technology stack", ar.XPoweredBy, "")
	}

	// Low findings
	for _, exif := range ar.ExifImages {
		title := "EXIF Metadata Found"
		desc := "Image contains EXIF metadata"
		if exif.HasGPS {
			title = "GPS Coordinates in Image"
			desc = "Image contains GPS coordinates - critical privacy risk"
			s.addFinding("clearnet_ip", title, desc, exif.ImageURL, "") // Treat GPS as critical
		} else {
			s.addFinding("exif_metadata", title, desc, exif.ImageURL, "")
		}
	}

	// Info findings
	for _, btc := range ar.BitcoinAddresses {
		s.addFinding("bitcoin_address_"+btc.Type, "Bitcoin Address",
			"Bitcoin address found", btc.Address, btc.Context)
	}
	for _, xmr := range ar.MoneroAddresses {
		s.addFinding("monero_address", "Monero Address",
			"Monero address found", xmr.Address, xmr.Context)
	}
	for _, eth := range ar.EthereumAddresses {
		s.addFinding("ethereum_address", "Ethereum Address",
			"Ethereum address found", eth.Address, eth.Context)
	}
	for _, onion := range ar.LinkedOnions {
		findingType := "onion_link_v3"
		if onion.Version == 2 {
			findingType = "onion_link_v2"
		}
		s.addFinding(findingType, "Linked Onion Address",
			"Related onion address found", onion.Address, onion.Context)
	}
}

// addFinding adds a finding to the report.
func (s *SimpleReport) addFinding(findingType, title, description, value, location string) {
	info := GetFindingInfo(findingType)
	s.Findings = append(s.Findings, Finding{
		Type:           findingType,
		Severity:       info.Severity,
		SeverityText:   info.Severity.String(),
		Title:          title,
		Description:    description,
		Impact:         info.Impact,
		Recommendation: info.Recommendation,
		Value:          value,
		Location:       location,
	})
}

// countBySeverity counts findings by severity level.
func (s *SimpleReport) countBySeverity() {
	for _, f := range s.Findings {
		switch f.Severity {
		case SeverityCritical:
			s.CriticalCount++
		case SeverityHigh:
			s.HighCount++
		case SeverityMedium:
			s.MediumCount++
		case SeverityLow:
			s.LowCount++
		case SeverityInfo:
			s.InfoCount++
		}
	}
}

// TotalFindings returns the total number of findings.
func (s *SimpleReport) TotalFindings() int {
	return len(s.Findings)
}

// HasFindings returns true if there are any findings.
func (s *SimpleReport) HasFindings() bool {
	return len(s.Findings) > 0
}

// GetFindingsBySeverity returns findings filtered by severity.
func (s *SimpleReport) GetFindingsBySeverity(severity Severity) []Finding {
	var result []Finding
	for _, f := range s.Findings {
		if f.Severity == severity {
			result = append(result, f)
		}
	}
	return result
}
