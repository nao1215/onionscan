package model

import "testing"

// TestSeverityString tests the String method of Severity.
func TestSeverityString(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		severity Severity
		expected string
	}{
		{SeverityInfo, "INFO"},
		{SeverityLow, "LOW"},
		{SeverityMedium, "MEDIUM"},
		{SeverityHigh, "HIGH"},
		{SeverityCritical, "CRITICAL"},
		{Severity(999), "UNKNOWN"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			t.Parallel()
			if tc.severity.String() != tc.expected {
				t.Errorf("got %q, expected %q", tc.severity.String(), tc.expected)
			}
		})
	}
}

// TestGetSeverity tests the GetSeverity function.
func TestGetSeverity(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		findingType string
		expected    Severity
	}{
		// Critical findings
		{"private_key_v3", SeverityCritical},
		{"private_key_v2", SeverityCritical},
		{"clearnet_ip", SeverityCritical},

		// High findings
		{"apache_mod_status", SeverityHigh},
		{"google_analytics_ga4", SeverityHigh},
		{"cloudflare_detected", SeverityHigh},

		// Medium findings
		{"email_address", SeverityMedium},
		{"social_telegram", SeverityMedium},

		// Low findings
		{"exif_metadata", SeverityLow},
		{"ssh_fingerprint", SeverityLow},

		// Info findings
		{"bitcoin_address_legacy", SeverityInfo},
		{"monero_address", SeverityInfo},

		// Unknown finding type defaults to Info
		{"unknown_type", SeverityInfo},
	}

	for _, tc := range testCases {
		t.Run(tc.findingType, func(t *testing.T) {
			t.Parallel()
			result := GetSeverity(tc.findingType)
			if result != tc.expected {
				t.Errorf("GetSeverity(%q) = %v, expected %v", tc.findingType, result, tc.expected)
			}
		})
	}
}

// TestSeverityOrdering tests that severity levels are ordered correctly.
// Info < Low < Medium < High < Critical
func TestSeverityOrdering(t *testing.T) {
	t.Parallel()

	if SeverityInfo >= SeverityLow {
		t.Error("expected SeverityInfo < SeverityLow")
	}
	if SeverityLow >= SeverityMedium {
		t.Error("expected SeverityLow < SeverityMedium")
	}
	if SeverityMedium >= SeverityHigh {
		t.Error("expected SeverityMedium < SeverityHigh")
	}
	if SeverityHigh >= SeverityCritical {
		t.Error("expected SeverityHigh < SeverityCritical")
	}
}

// TestGetFindingInfo tests the GetFindingInfo function.
func TestGetFindingInfo(t *testing.T) {
	t.Parallel()

	t.Run("returns correct info for known finding type", func(t *testing.T) {
		t.Parallel()

		info := GetFindingInfo("private_key_v3")

		if info.Severity != SeverityCritical {
			t.Errorf("expected SeverityCritical, got %v", info.Severity)
		}
		if info.Impact == "" {
			t.Error("expected non-empty Impact")
		}
		if info.Recommendation == "" {
			t.Error("expected non-empty Recommendation")
		}
	})

	t.Run("returns default info for unknown finding type", func(t *testing.T) {
		t.Parallel()

		info := GetFindingInfo("completely_unknown_type")

		if info.Severity != SeverityInfo {
			t.Errorf("expected SeverityInfo for unknown type, got %v", info.Severity)
		}
		if info.Impact == "" {
			t.Error("expected non-empty default Impact")
		}
		if info.Recommendation == "" {
			t.Error("expected non-empty default Recommendation")
		}
	})

	t.Run("returns correct info for various severity levels", func(t *testing.T) {
		t.Parallel()

		testCases := []struct {
			findingType string
			expected    Severity
		}{
			{"clearnet_ip", SeverityCritical},
			{"apache_mod_status", SeverityHigh},
			{"email_address", SeverityMedium},
			{"exif_metadata", SeverityLow},
			{"bitcoin_address_legacy", SeverityInfo},
		}

		for _, tc := range testCases {
			info := GetFindingInfo(tc.findingType)
			if info.Severity != tc.expected {
				t.Errorf("GetFindingInfo(%q).Severity = %v, expected %v",
					tc.findingType, info.Severity, tc.expected)
			}
		}
	})
}

// TestFindingInfoStruct tests the FindingInfo struct.
func TestFindingInfoStruct(t *testing.T) {
	t.Parallel()

	t.Run("all fields can be set", func(t *testing.T) {
		t.Parallel()

		info := FindingInfo{
			Severity:       SeverityHigh,
			Impact:         "Test impact",
			Recommendation: "Test recommendation",
		}

		if info.Severity != SeverityHigh {
			t.Errorf("expected SeverityHigh, got %v", info.Severity)
		}
		if info.Impact != "Test impact" {
			t.Errorf("expected 'Test impact', got %q", info.Impact)
		}
		if info.Recommendation != "Test recommendation" {
			t.Errorf("expected 'Test recommendation', got %q", info.Recommendation)
		}
	})
}

// TestFindingInfoMappingCompleteness tests that all finding types have proper info.
func TestFindingInfoMappingCompleteness(t *testing.T) {
	t.Parallel()

	// Test a sample of finding types to ensure they have complete info
	findingTypes := []string{
		"private_key_v3",
		"clearnet_ip",
		"apache_mod_status",
		"google_analytics_ga4",
		"email_address",
		"exif_metadata",
		"bitcoin_address_legacy",
	}

	for _, findingType := range findingTypes {
		t.Run(findingType, func(t *testing.T) {
			t.Parallel()

			info := GetFindingInfo(findingType)

			if info.Impact == "" {
				t.Errorf("finding type %q has empty Impact", findingType)
			}
			if info.Recommendation == "" {
				t.Errorf("finding type %q has empty Recommendation", findingType)
			}
			if info.Impact == "Unknown finding type. Review manually." {
				t.Errorf("finding type %q returned default Impact", findingType)
			}
		})
	}
}
