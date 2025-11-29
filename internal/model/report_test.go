package model

import (
	"testing"
	"time"
)

// TestNewOnionScanReport tests the OnionScanReport constructor.
func TestNewOnionScanReport(t *testing.T) {
	t.Parallel()

	hiddenService := "example.onion"
	report := NewOnionScanReport(hiddenService)

	t.Run("sets hidden service address", func(t *testing.T) {
		t.Parallel()
		if report.HiddenService != hiddenService {
			t.Errorf("got %q, expected %q", report.HiddenService, hiddenService)
		}
	})

	t.Run("defaults to onion version 3", func(t *testing.T) {
		t.Parallel()
		if report.OnionVersion != 3 {
			t.Errorf("got %d, expected 3", report.OnionVersion)
		}
	})

	t.Run("sets scan timestamp", func(t *testing.T) {
		t.Parallel()
		if report.DateScanned.IsZero() {
			t.Error("expected DateScanned to be set")
		}
		// Should be recent (within last second)
		if time.Since(report.DateScanned) > time.Second {
			t.Error("DateScanned is too old")
		}
	})

	t.Run("initializes Crawls map", func(t *testing.T) {
		t.Parallel()
		if report.Crawls == nil {
			t.Error("expected Crawls to be initialized")
		}
	})

	t.Run("initializes PageCache map", func(t *testing.T) {
		t.Parallel()
		if report.PageCache == nil {
			t.Error("expected PageCache to be initialized")
		}
	})

	t.Run("initializes AnonymityReport", func(t *testing.T) {
		t.Parallel()
		if report.AnonymityReport == nil {
			t.Error("expected AnonymityReport to be initialized")
		}
	})
}

// TestOnionScanReportAddPage tests the AddPage method.
func TestOnionScanReportAddPage(t *testing.T) {
	t.Parallel()

	report := NewOnionScanReport("example.onion")
	page := &Page{
		URL:        "http://example.onion/index.html",
		StatusCode: 200,
	}

	report.AddPage(page.URL, page)

	t.Run("adds URL to Crawls with status code", func(t *testing.T) {
		t.Parallel()
		if status, ok := report.Crawls[page.URL]; !ok {
			t.Error("expected URL to be in Crawls")
		} else if status != 200 {
			t.Errorf("got status %d, expected 200", status)
		}
	})

	t.Run("adds page to PageCache", func(t *testing.T) {
		t.Parallel()
		if cached := report.PageCache[page.URL]; cached != page {
			t.Error("expected page to be in PageCache")
		}
	})
}

// TestOnionScanReportGetPage tests the GetPage method.
func TestOnionScanReportGetPage(t *testing.T) {
	t.Parallel()

	report := NewOnionScanReport("example.onion")
	page := &Page{
		URL:        "http://example.onion/index.html",
		StatusCode: 200,
	}
	report.AddPage(page.URL, page)

	t.Run("returns cached page", func(t *testing.T) {
		t.Parallel()
		if got := report.GetPage(page.URL); got != page {
			t.Error("expected to get cached page")
		}
	})

	t.Run("returns nil for uncached URL", func(t *testing.T) {
		t.Parallel()
		if got := report.GetPage("http://example.onion/notcached"); got != nil {
			t.Error("expected nil for uncached URL")
		}
	})
}

// TestAnonymityReportAddEmailAddress tests deduplication of email addresses.
func TestAnonymityReportAddEmailAddress(t *testing.T) {
	t.Parallel()

	ar := NewAnonymityReport()

	ar.AddEmailAddress("test@example.com")
	ar.AddEmailAddress("another@example.com")
	ar.AddEmailAddress("test@example.com") // Duplicate

	if len(ar.EmailAddresses) != 2 {
		t.Errorf("got %d addresses, expected 2", len(ar.EmailAddresses))
	}
}

// TestAnonymityReportAddIPAddress tests deduplication of IP addresses.
func TestAnonymityReportAddIPAddress(t *testing.T) {
	t.Parallel()

	ar := NewAnonymityReport()

	ar.AddIPAddress("192.168.1.1")
	ar.AddIPAddress("10.0.0.1")
	ar.AddIPAddress("192.168.1.1") // Duplicate

	if len(ar.IPAddresses) != 2 {
		t.Errorf("got %d addresses, expected 2", len(ar.IPAddresses))
	}
}

// TestAnonymityReportAddLinkedOnion tests deduplication of onion links.
func TestAnonymityReportAddLinkedOnion(t *testing.T) {
	t.Parallel()

	ar := NewAnonymityReport()

	link1 := OnionLink{Address: "example1.onion", Version: 3}
	link2 := OnionLink{Address: "example2.onion", Version: 3}
	link3 := OnionLink{Address: "example1.onion", Version: 3} // Duplicate

	ar.AddLinkedOnion(link1)
	ar.AddLinkedOnion(link2)
	ar.AddLinkedOnion(link3)

	if len(ar.LinkedOnions) != 2 {
		t.Errorf("got %d links, expected 2", len(ar.LinkedOnions))
	}
}

// TestAnonymityReportHasCriticalFindings tests critical finding detection.
func TestAnonymityReportHasCriticalFindings(t *testing.T) {
	t.Parallel()

	t.Run("returns false for empty report", func(t *testing.T) {
		t.Parallel()
		ar := NewAnonymityReport()
		if ar.HasCriticalFindings() {
			t.Error("expected false for empty report")
		}
	})

	t.Run("returns true for private key exposed", func(t *testing.T) {
		t.Parallel()
		ar := NewAnonymityReport()
		ar.PrivateKeyExposed = true
		if !ar.HasCriticalFindings() {
			t.Error("expected true for private key exposed")
		}
	})

	t.Run("returns true for hostname file exposed", func(t *testing.T) {
		t.Parallel()
		ar := NewAnonymityReport()
		ar.HostnameFileExposed = true
		if !ar.HasCriticalFindings() {
			t.Error("expected true for hostname file exposed")
		}
	})

	t.Run("returns true for IP addresses found", func(t *testing.T) {
		t.Parallel()
		ar := NewAnonymityReport()
		ar.AddIPAddress("192.168.1.1")
		if !ar.HasCriticalFindings() {
			t.Error("expected true for IP addresses found")
		}
	})
}

// TestAnonymityReportHasHighFindings tests high severity finding detection.
func TestAnonymityReportHasHighFindings(t *testing.T) {
	t.Parallel()

	t.Run("returns false for empty report", func(t *testing.T) {
		t.Parallel()
		ar := NewAnonymityReport()
		if ar.HasHighFindings() {
			t.Error("expected false for empty report")
		}
	})

	t.Run("returns true for Apache mod_status", func(t *testing.T) {
		t.Parallel()
		ar := NewAnonymityReport()
		ar.ApacheModStatusFound = true
		if !ar.HasHighFindings() {
			t.Error("expected true for Apache mod_status")
		}
	})

	t.Run("returns true for Cloudflare detected", func(t *testing.T) {
		t.Parallel()
		ar := NewAnonymityReport()
		ar.CloudflareDetected = true
		if !ar.HasHighFindings() {
			t.Error("expected true for Cloudflare detected")
		}
	})

	t.Run("returns true for analytics IDs", func(t *testing.T) {
		t.Parallel()
		ar := NewAnonymityReport()
		ar.AddAnalyticsID(AnalyticsID{ID: "G-12345", Type: "ga4"})
		if !ar.HasHighFindings() {
			t.Error("expected true for analytics IDs")
		}
	})
}

// TestOnionScanReportAddFinding tests the AddFinding method.
func TestOnionScanReportAddFinding(t *testing.T) {
	t.Parallel()

	t.Run("initializes SimpleReport if nil", func(t *testing.T) {
		t.Parallel()

		report := NewOnionScanReport("example.onion")
		report.SimpleReport = nil

		finding := Finding{
			Type:     "test_finding",
			Title:    "Test Finding",
			Severity: SeverityMedium,
			Value:    "test value",
		}

		report.AddFinding(finding)

		if report.SimpleReport == nil {
			t.Fatal("expected SimpleReport to be initialized")
		}
		if len(report.SimpleReport.Findings) != 1 {
			t.Errorf("expected 1 finding, got %d", len(report.SimpleReport.Findings))
		}
	})

	t.Run("deduplicates findings", func(t *testing.T) {
		t.Parallel()

		report := NewOnionScanReport("example.onion")

		finding := Finding{
			Type:     "test_finding",
			Title:    "Test Finding",
			Severity: SeverityMedium,
			Value:    "test value",
			Location: "http://example.onion/page",
		}

		report.AddFinding(finding)
		report.AddFinding(finding) // Duplicate

		if len(report.SimpleReport.Findings) != 1 {
			t.Errorf("expected 1 finding after deduplication, got %d", len(report.SimpleReport.Findings))
		}
	})

	t.Run("counts severity levels correctly", func(t *testing.T) {
		t.Parallel()

		report := NewOnionScanReport("example.onion")

		report.AddFinding(Finding{Type: "critical1", Severity: SeverityCritical, Value: "c1"})
		report.AddFinding(Finding{Type: "critical2", Severity: SeverityCritical, Value: "c2"})
		report.AddFinding(Finding{Type: "high1", Severity: SeverityHigh, Value: "h1"})
		report.AddFinding(Finding{Type: "medium1", Severity: SeverityMedium, Value: "m1"})
		report.AddFinding(Finding{Type: "low1", Severity: SeverityLow, Value: "l1"})
		report.AddFinding(Finding{Type: "info1", Severity: SeverityInfo, Value: "i1"})

		if report.SimpleReport.CriticalCount != 2 {
			t.Errorf("expected CriticalCount 2, got %d", report.SimpleReport.CriticalCount)
		}
		if report.SimpleReport.HighCount != 1 {
			t.Errorf("expected HighCount 1, got %d", report.SimpleReport.HighCount)
		}
		if report.SimpleReport.MediumCount != 1 {
			t.Errorf("expected MediumCount 1, got %d", report.SimpleReport.MediumCount)
		}
		if report.SimpleReport.LowCount != 1 {
			t.Errorf("expected LowCount 1, got %d", report.SimpleReport.LowCount)
		}
		if report.SimpleReport.InfoCount != 1 {
			t.Errorf("expected InfoCount 1, got %d", report.SimpleReport.InfoCount)
		}
	})
}

// TestCertificateInfo tests the CertificateInfo struct.
func TestCertificateInfo(t *testing.T) {
	t.Parallel()

	info := CertificateInfo{
		Subject:      "CN=example.com",
		Issuer:       "CN=Test CA",
		SerialNumber: "1234",
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		SANs:         []string{"example.com", "*.example.com"},
		IsCA:         false,
	}

	if info.Subject != "CN=example.com" {
		t.Errorf("unexpected Subject: %s", info.Subject)
	}
	if len(info.SANs) != 2 {
		t.Errorf("expected 2 SANs, got %d", len(info.SANs))
	}
}

// TestBitcoinService tests the BitcoinService struct.
func TestBitcoinService(t *testing.T) {
	t.Parallel()

	service := BitcoinService{
		UserAgent:       "/Satoshi:0.21.0/",
		ProtocolVersion: 70016,
		PeerAddresses:   []string{"peer1.onion", "peer2.onion"},
	}

	if service.UserAgent != "/Satoshi:0.21.0/" {
		t.Errorf("unexpected UserAgent: %s", service.UserAgent)
	}
	if service.ProtocolVersion != 70016 {
		t.Errorf("expected protocol version 70016, got %d", service.ProtocolVersion)
	}
}

// TestCertInfo tests the CertInfo struct.
func TestCertInfo(t *testing.T) {
	t.Parallel()

	info := CertInfo{
		Subject:    "CN=example.onion",
		Issuer:     "CN=Self-Signed",
		NotBefore:  "2024-01-01T00:00:00Z",
		NotAfter:   "2025-01-01T00:00:00Z",
		CommonName: "example.onion",
		SANs:       []string{"example.onion"},
	}

	if info.CommonName != "example.onion" {
		t.Errorf("unexpected CommonName: %s", info.CommonName)
	}
}

// TestPGPKey tests the PGPKey struct.
func TestPGPKey(t *testing.T) {
	t.Parallel()

	key := PGPKey{
		Fingerprint:  "ABCD1234",
		Identity:     "user@example.com",
		ArmoredKey:   "-----BEGIN PGP PUBLIC KEY-----",
		CreationTime: time.Now(),
	}

	if key.Fingerprint != "ABCD1234" {
		t.Errorf("unexpected Fingerprint: %s", key.Fingerprint)
	}
}

// TestAnonymityReportAddBitcoinAddress tests deduplication of Bitcoin addresses.
func TestAnonymityReportAddBitcoinAddress(t *testing.T) {
	t.Parallel()

	ar := NewAnonymityReport()

	addr1 := CryptoAddress{Address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Type: "legacy"}
	addr2 := CryptoAddress{Address: "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", Type: "p2sh"}
	addr3 := CryptoAddress{Address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Type: "legacy"} // Duplicate

	ar.AddBitcoinAddress(addr1)
	ar.AddBitcoinAddress(addr2)
	ar.AddBitcoinAddress(addr3)

	if len(ar.BitcoinAddresses) != 2 {
		t.Errorf("got %d addresses, expected 2", len(ar.BitcoinAddresses))
	}
}

// TestAnonymityReportAddMoneroAddress tests deduplication of Monero addresses.
func TestAnonymityReportAddMoneroAddress(t *testing.T) {
	t.Parallel()

	ar := NewAnonymityReport()

	addr1 := CryptoAddress{Address: "4..." + "A" + "1234567890123456789012345678901234567890", Type: "standard"}
	addr2 := CryptoAddress{Address: "4..." + "B" + "1234567890123456789012345678901234567890", Type: "standard"}
	addr3 := CryptoAddress{Address: "4..." + "A" + "1234567890123456789012345678901234567890", Type: "standard"} // Duplicate

	ar.AddMoneroAddress(addr1)
	ar.AddMoneroAddress(addr2)
	ar.AddMoneroAddress(addr3)

	if len(ar.MoneroAddresses) != 2 {
		t.Errorf("got %d addresses, expected 2", len(ar.MoneroAddresses))
	}
}

// TestAnonymityReportAddEthereumAddress tests deduplication of Ethereum addresses.
func TestAnonymityReportAddEthereumAddress(t *testing.T) {
	t.Parallel()

	ar := NewAnonymityReport()

	addr1 := CryptoAddress{Address: "0x1234567890123456789012345678901234567890", Type: "standard"}
	addr2 := CryptoAddress{Address: "0xabcdef1234567890123456789012345678901234", Type: "standard"}
	addr3 := CryptoAddress{Address: "0x1234567890123456789012345678901234567890", Type: "standard"} // Duplicate

	ar.AddEthereumAddress(addr1)
	ar.AddEthereumAddress(addr2)
	ar.AddEthereumAddress(addr3)

	if len(ar.EthereumAddresses) != 2 {
		t.Errorf("got %d addresses, expected 2", len(ar.EthereumAddresses))
	}
}

// TestAnonymityReportAddSocialLink tests deduplication of social links.
func TestAnonymityReportAddSocialLink(t *testing.T) {
	t.Parallel()

	ar := NewAnonymityReport()

	link1 := SocialLink{Platform: "twitter", Username: "user1", URL: "https://twitter.com/user1"}
	link2 := SocialLink{Platform: "telegram", Username: "user2", URL: "https://t.me/user2"}
	link3 := SocialLink{Platform: "twitter", Username: "user1", URL: "https://twitter.com/user1"} // Duplicate

	ar.AddSocialLink(link1)
	ar.AddSocialLink(link2)
	ar.AddSocialLink(link3)

	if len(ar.SocialLinks) != 2 {
		t.Errorf("got %d links, expected 2", len(ar.SocialLinks))
	}
}

// TestAnonymityReportAddRelatedClearnetDomain tests deduplication of clearnet domains.
func TestAnonymityReportAddRelatedClearnetDomain(t *testing.T) {
	t.Parallel()

	ar := NewAnonymityReport()

	ar.AddRelatedClearnetDomain("example.com")
	ar.AddRelatedClearnetDomain("another.com")
	ar.AddRelatedClearnetDomain("example.com") // Duplicate

	if len(ar.RelatedClearnetDomains) != 2 {
		t.Errorf("got %d domains, expected 2", len(ar.RelatedClearnetDomains))
	}
}

// TestNewSimpleReport tests the NewSimpleReport function.
func TestNewSimpleReport(t *testing.T) {
	t.Parallel()

	t.Run("creates report from OnionScanReport", func(t *testing.T) {
		t.Parallel()

		report := NewOnionScanReport("example.onion")
		report.WebDetected = true
		report.SSHDetected = true
		report.AnonymityReport.AddIPAddress("192.168.1.1")
		report.AnonymityReport.AddEmailAddress("test@example.com")

		simple := NewSimpleReport(report)

		if simple.HiddenService != "example.onion" {
			t.Errorf("expected 'example.onion', got %q", simple.HiddenService)
		}
		if len(simple.DetectedServices) != 2 {
			t.Errorf("expected 2 detected services, got %d", len(simple.DetectedServices))
		}
		if len(simple.Findings) == 0 {
			t.Error("expected findings to be collected")
		}
	})

	t.Run("handles error message", func(t *testing.T) {
		t.Parallel()

		report := NewOnionScanReport("example.onion")
		report.Error = &testError{msg: "test error"}

		simple := NewSimpleReport(report)

		if simple.Error != "test error" {
			t.Errorf("expected error message 'test error', got %q", simple.Error)
		}
	})

	t.Run("handles timed out", func(t *testing.T) {
		t.Parallel()

		report := NewOnionScanReport("example.onion")
		report.TimedOut = true

		simple := NewSimpleReport(report)

		if !simple.TimedOut {
			t.Error("expected TimedOut to be true")
		}
	})
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

// TestSimpleReportMethods tests SimpleReport helper methods.
func TestSimpleReportMethods(t *testing.T) {
	t.Parallel()

	t.Run("TotalFindings returns count", func(t *testing.T) {
		t.Parallel()

		report := &SimpleReport{
			Findings: []Finding{
				{Type: "test1", Severity: SeverityHigh},
				{Type: "test2", Severity: SeverityLow},
			},
		}

		if report.TotalFindings() != 2 {
			t.Errorf("expected 2, got %d", report.TotalFindings())
		}
	})

	t.Run("HasFindings returns true when findings exist", func(t *testing.T) {
		t.Parallel()

		report := &SimpleReport{
			Findings: []Finding{{Type: "test1", Severity: SeverityHigh}},
		}

		if !report.HasFindings() {
			t.Error("expected true")
		}
	})

	t.Run("HasFindings returns false when no findings", func(t *testing.T) {
		t.Parallel()

		report := &SimpleReport{}

		if report.HasFindings() {
			t.Error("expected false")
		}
	})

	t.Run("GetFindingsBySeverity filters correctly", func(t *testing.T) {
		t.Parallel()

		report := &SimpleReport{
			Findings: []Finding{
				{Type: "test1", Severity: SeverityHigh},
				{Type: "test2", Severity: SeverityLow},
				{Type: "test3", Severity: SeverityHigh},
			},
		}

		highFindings := report.GetFindingsBySeverity(SeverityHigh)
		if len(highFindings) != 2 {
			t.Errorf("expected 2 high findings, got %d", len(highFindings))
		}

		lowFindings := report.GetFindingsBySeverity(SeverityLow)
		if len(lowFindings) != 1 {
			t.Errorf("expected 1 low finding, got %d", len(lowFindings))
		}
	})
}

// TestCollectDetectedServices tests all service detection.
func TestCollectDetectedServices(t *testing.T) {
	t.Parallel()

	report := NewOnionScanReport("example.onion")
	report.WebDetected = true
	report.TLSDetected = true
	report.SSHDetected = true
	report.FTPDetected = true
	report.SMTPDetected = true
	report.MongoDBDetected = true
	report.RedisDetected = true
	report.PostgreSQLDetected = true
	report.MySQLDetected = true
	report.BitcoinDetected = true

	simple := NewSimpleReport(report)

	expectedServices := 10
	if len(simple.DetectedServices) != expectedServices {
		t.Errorf("expected %d services, got %d", expectedServices, len(simple.DetectedServices))
	}
}

// TestCollectFindings tests various finding types.
func TestCollectFindings(t *testing.T) {
	t.Parallel()

	t.Run("collects critical findings", func(t *testing.T) {
		t.Parallel()

		report := NewOnionScanReport("example.onion")
		report.AnonymityReport.PrivateKeyExposed = true
		report.AnonymityReport.PrivateKeyType = "v3"
		report.AnonymityReport.HostnameFileExposed = true
		report.AnonymityReport.AddIPAddress("192.168.1.1")

		simple := NewSimpleReport(report)

		// Should have at least 3 critical findings
		criticalCount := 0
		for _, f := range simple.Findings {
			if f.Severity == SeverityCritical {
				criticalCount++
			}
		}
		if criticalCount < 3 {
			t.Errorf("expected at least 3 critical findings, got %d", criticalCount)
		}
	})

	t.Run("collects high findings", func(t *testing.T) {
		t.Parallel()

		report := NewOnionScanReport("example.onion")
		report.AnonymityReport.ApacheModStatusFound = true
		report.AnonymityReport.NginxStatusFound = true
		report.AnonymityReport.CloudflareDetected = true
		report.AnonymityReport.CloudflareRayID = "test-ray-id"
		report.AnonymityReport.AWSResources = append(report.AnonymityReport.AWSResources, AWSResource{
			Type:       "s3",
			Identifier: "bucket-name",
		})
		report.AnonymityReport.CSPExternalDomains = append(report.AnonymityReport.CSPExternalDomains, "cdn.example.com")
		report.AnonymityReport.APIEndpoints = append(report.AnonymityReport.APIEndpoints, APIEndpoint{
			URL:     "https://api.example.com",
			Type:    "fetch",
			Context: "script.js",
		})

		simple := NewSimpleReport(report)

		highCount := 0
		for _, f := range simple.Findings {
			if f.Severity == SeverityHigh {
				highCount++
			}
		}
		if highCount < 4 {
			t.Errorf("expected at least 4 high findings, got %d", highCount)
		}
	})

	t.Run("collects medium findings", func(t *testing.T) {
		t.Parallel()

		report := NewOnionScanReport("example.onion")
		report.AnonymityReport.AddEmailAddress("test@example.com")
		report.AnonymityReport.AddSocialLink(SocialLink{Platform: "telegram", Username: "user"})
		report.AnonymityReport.OpenDirectories = append(report.AnonymityReport.OpenDirectories, "/data/")
		report.AnonymityReport.ServerVersion = "Apache/2.4.41"
		report.AnonymityReport.XPoweredBy = "PHP/7.4"

		simple := NewSimpleReport(report)

		mediumCount := 0
		for _, f := range simple.Findings {
			if f.Severity == SeverityMedium {
				mediumCount++
			}
		}
		if mediumCount < 4 {
			t.Errorf("expected at least 4 medium findings, got %d", mediumCount)
		}
	})

	t.Run("collects low findings from EXIF data", func(t *testing.T) {
		t.Parallel()

		report := NewOnionScanReport("example.onion")
		report.AnonymityReport.ExifImages = append(report.AnonymityReport.ExifImages, ExifData{
			ImageURL: "/images/photo.jpg",
			Make:     "Canon",
			Model:    "EOS 5D",
			HasGPS:   false,
		})

		simple := NewSimpleReport(report)

		lowCount := 0
		for _, f := range simple.Findings {
			if f.Severity == SeverityLow {
				lowCount++
			}
		}
		if lowCount < 1 {
			t.Errorf("expected at least 1 low finding, got %d", lowCount)
		}
	})

	t.Run("treats GPS in EXIF as critical", func(t *testing.T) {
		t.Parallel()

		report := NewOnionScanReport("example.onion")
		report.AnonymityReport.ExifImages = append(report.AnonymityReport.ExifImages, ExifData{
			ImageURL: "/images/photo.jpg",
			HasGPS:   true,
		})

		simple := NewSimpleReport(report)

		hasCriticalGPS := false
		for _, f := range simple.Findings {
			if f.Severity == SeverityCritical && f.Title == "GPS Coordinates in Image" {
				hasCriticalGPS = true
				break
			}
		}
		if !hasCriticalGPS {
			t.Error("expected GPS finding to be critical")
		}
	})

	t.Run("collects info findings from crypto addresses", func(t *testing.T) {
		t.Parallel()

		report := NewOnionScanReport("example.onion")
		report.AnonymityReport.AddBitcoinAddress(CryptoAddress{Address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Type: "legacy"})
		report.AnonymityReport.AddMoneroAddress(CryptoAddress{Address: "4..." + "1234567890123456789012345678901234567890", Type: "standard"})
		report.AnonymityReport.AddEthereumAddress(CryptoAddress{Address: "0x1234567890123456789012345678901234567890", Type: "standard"})
		report.AnonymityReport.AddLinkedOnion(OnionLink{Address: "example.onion", Version: 3})
		report.AnonymityReport.AddLinkedOnion(OnionLink{Address: "deprecated.onion", Version: 2})

		simple := NewSimpleReport(report)

		infoCount := 0
		for _, f := range simple.Findings {
			if f.Severity == SeverityInfo {
				infoCount++
			}
		}
		if infoCount < 5 {
			t.Errorf("expected at least 5 info findings, got %d", infoCount)
		}
	})
}

// TestAnonymityReportHighFindingsAllCases tests all high finding conditions.
func TestAnonymityReportHighFindingsAllCases(t *testing.T) {
	t.Parallel()

	t.Run("returns true for NginxStatusFound", func(t *testing.T) {
		t.Parallel()
		ar := NewAnonymityReport()
		ar.NginxStatusFound = true
		if !ar.HasHighFindings() {
			t.Error("expected true for NginxStatusFound")
		}
	})

	t.Run("returns true for AWSResources", func(t *testing.T) {
		t.Parallel()
		ar := NewAnonymityReport()
		ar.AWSResources = append(ar.AWSResources, AWSResource{Type: "s3"})
		if !ar.HasHighFindings() {
			t.Error("expected true for AWSResources")
		}
	})

	t.Run("returns true for CSPExternalDomains", func(t *testing.T) {
		t.Parallel()
		ar := NewAnonymityReport()
		ar.CSPExternalDomains = append(ar.CSPExternalDomains, "example.com")
		if !ar.HasHighFindings() {
			t.Error("expected true for CSPExternalDomains")
		}
	})

	t.Run("returns true for APIEndpoints", func(t *testing.T) {
		t.Parallel()
		ar := NewAnonymityReport()
		ar.APIEndpoints = append(ar.APIEndpoints, APIEndpoint{URL: "https://api.example.com"})
		if !ar.HasHighFindings() {
			t.Error("expected true for APIEndpoints")
		}
	})
}

// TestAnonymityReportAddAnalyticsID tests AddAnalyticsID deduplication.
func TestAnonymityReportAddAnalyticsID(t *testing.T) {
	t.Parallel()

	t.Run("adds new analytics ID", func(t *testing.T) {
		t.Parallel()

		ar := NewAnonymityReport()
		ar.AddAnalyticsID(AnalyticsID{ID: "G-12345678", Type: "ga4"})

		if len(ar.AnalyticsIDs) != 1 {
			t.Errorf("expected 1 analytics ID, got %d", len(ar.AnalyticsIDs))
		}
	})

	t.Run("deduplicates same analytics ID", func(t *testing.T) {
		t.Parallel()

		ar := NewAnonymityReport()
		ar.AddAnalyticsID(AnalyticsID{ID: "G-12345678", Type: "ga4"})
		ar.AddAnalyticsID(AnalyticsID{ID: "G-12345678", Type: "ga4"})

		if len(ar.AnalyticsIDs) != 1 {
			t.Errorf("expected 1 analytics ID after dedup, got %d", len(ar.AnalyticsIDs))
		}
	})

	t.Run("allows different IDs of same type", func(t *testing.T) {
		t.Parallel()

		ar := NewAnonymityReport()
		ar.AddAnalyticsID(AnalyticsID{ID: "G-12345678", Type: "ga4"})
		ar.AddAnalyticsID(AnalyticsID{ID: "G-87654321", Type: "ga4"})

		if len(ar.AnalyticsIDs) != 2 {
			t.Errorf("expected 2 analytics IDs, got %d", len(ar.AnalyticsIDs))
		}
	})
}
