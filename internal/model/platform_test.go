package model

import (
	"testing"
)

func TestSocialPlatform(t *testing.T) {
	t.Parallel()

	t.Run("String returns correct value", func(t *testing.T) {
		t.Parallel()
		if got := SocialPlatformTwitter.String(); got != "twitter" {
			t.Errorf("expected twitter, got %s", got)
		}
		if got := SocialPlatformUnknown.String(); got != "unknown" {
			t.Errorf("expected unknown, got %s", got)
		}
	})

	t.Run("IsValid returns true for known platforms", func(t *testing.T) {
		t.Parallel()
		if !SocialPlatformTwitter.IsValid() {
			t.Error("expected twitter to be valid")
		}
		if SocialPlatformUnknown.IsValid() {
			t.Error("expected unknown to be invalid")
		}
	})

	t.Run("DefaultSeverity returns correct values", func(t *testing.T) {
		t.Parallel()
		if got := SocialPlatformLinkedIn.DefaultSeverity(); got != SeverityCritical {
			t.Errorf("expected critical for linkedin, got %v", got)
		}
		if got := SocialPlatformTwitter.DefaultSeverity(); got != SeverityHigh {
			t.Errorf("expected high for twitter, got %v", got)
		}
		if got := SocialPlatformMatrix.DefaultSeverity(); got != SeverityLow {
			t.Errorf("expected low for matrix, got %v", got)
		}
	})

	t.Run("ParseSocialPlatform parses correctly", func(t *testing.T) {
		t.Parallel()
		if got := ParseSocialPlatform("twitter"); got != SocialPlatformTwitter {
			t.Errorf("expected twitter, got %v", got)
		}
		if got := ParseSocialPlatform("x"); got != SocialPlatformTwitter {
			t.Errorf("expected twitter for x, got %v", got)
		}
		if got := ParseSocialPlatform("invalid"); got != SocialPlatformUnknown {
			t.Errorf("expected unknown, got %v", got)
		}
	})
}

func TestAnalyticsPlatform(t *testing.T) {
	t.Parallel()

	t.Run("String returns correct value", func(t *testing.T) {
		t.Parallel()
		if got := AnalyticsPlatformGA4.String(); got != "ga4" {
			t.Errorf("expected ga4, got %s", got)
		}
		if got := AnalyticsPlatformUnknown.String(); got != "unknown" {
			t.Errorf("expected unknown, got %s", got)
		}
	})

	t.Run("IsValid returns true for known platforms", func(t *testing.T) {
		t.Parallel()
		if !AnalyticsPlatformGA4.IsValid() {
			t.Error("expected ga4 to be valid")
		}
		if AnalyticsPlatformUnknown.IsValid() {
			t.Error("expected unknown to be invalid")
		}
	})

	t.Run("IsCloudBased returns correct values", func(t *testing.T) {
		t.Parallel()
		if !AnalyticsPlatformGA4.IsCloudBased() {
			t.Error("expected ga4 to be cloud based")
		}
		if AnalyticsPlatformMatomo.IsCloudBased() {
			t.Error("expected matomo to not be cloud based")
		}
	})

	t.Run("DefaultSeverity returns correct values", func(t *testing.T) {
		t.Parallel()
		if got := AnalyticsPlatformGA4.DefaultSeverity(); got != SeverityCritical {
			t.Errorf("expected critical for ga4, got %v", got)
		}
		if got := AnalyticsPlatformMatomo.DefaultSeverity(); got != SeverityMedium {
			t.Errorf("expected medium for matomo, got %v", got)
		}
	})

	t.Run("ParseAnalyticsPlatform parses correctly", func(t *testing.T) {
		t.Parallel()
		if got := ParseAnalyticsPlatform("ga4"); got != AnalyticsPlatformGA4 {
			t.Errorf("expected ga4, got %v", got)
		}
		if got := ParseAnalyticsPlatform("invalid"); got != AnalyticsPlatformUnknown {
			t.Errorf("expected unknown, got %v", got)
		}
	})
}

func TestAPIDetectionMethod(t *testing.T) {
	t.Parallel()

	t.Run("String returns correct value", func(t *testing.T) {
		t.Parallel()
		if got := APIDetectionFetch.String(); got != "fetch" {
			t.Errorf("expected fetch, got %s", got)
		}
		if got := APIDetectionUnknown.String(); got != "unknown" {
			t.Errorf("expected unknown, got %s", got)
		}
	})

	t.Run("IsValid returns true for known methods", func(t *testing.T) {
		t.Parallel()
		if !APIDetectionFetch.IsValid() {
			t.Error("expected fetch to be valid")
		}
		if APIDetectionUnknown.IsValid() {
			t.Error("expected unknown to be invalid")
		}
	})

	t.Run("ParseAPIDetectionMethod parses correctly", func(t *testing.T) {
		t.Parallel()
		if got := ParseAPIDetectionMethod("fetch"); got != APIDetectionFetch {
			t.Errorf("expected fetch, got %v", got)
		}
		if got := ParseAPIDetectionMethod("websocket"); got != APIDetectionWebSocket {
			t.Errorf("expected websocket, got %v", got)
		}
		if got := ParseAPIDetectionMethod("invalid"); got != APIDetectionUnknown {
			t.Errorf("expected unknown, got %v", got)
		}
	})
}

func TestCryptoAddressType(t *testing.T) {
	t.Parallel()

	t.Run("String returns correct value", func(t *testing.T) {
		t.Parallel()
		if got := CryptoAddressTypeBTCLegacy.String(); got != "btc_legacy" {
			t.Errorf("expected btc_legacy, got %s", got)
		}
		if got := CryptoAddressTypeUnknown.String(); got != "unknown" {
			t.Errorf("expected unknown, got %s", got)
		}
	})

	t.Run("IsValid returns true for known types", func(t *testing.T) {
		t.Parallel()
		if !CryptoAddressTypeBTCLegacy.IsValid() {
			t.Error("expected btc_legacy to be valid")
		}
		if CryptoAddressTypeUnknown.IsValid() {
			t.Error("expected unknown to be invalid")
		}
	})

	t.Run("Currency returns correct value", func(t *testing.T) {
		t.Parallel()
		if got := CryptoAddressTypeBTCLegacy.Currency(); got != "Bitcoin" {
			t.Errorf("expected Bitcoin, got %s", got)
		}
		if got := CryptoAddressTypeETH.Currency(); got != "Ethereum" {
			t.Errorf("expected Ethereum, got %s", got)
		}
		if got := CryptoAddressTypeXMRStandard.Currency(); got != "Monero" {
			t.Errorf("expected Monero, got %s", got)
		}
	})

	t.Run("DefaultSeverity returns correct values", func(t *testing.T) {
		t.Parallel()
		if got := CryptoAddressTypeBTCLegacy.DefaultSeverity(); got != SeverityHigh {
			t.Errorf("expected high for bitcoin, got %v", got)
		}
		if got := CryptoAddressTypeXMRStandard.DefaultSeverity(); got != SeverityMedium {
			t.Errorf("expected medium for monero, got %v", got)
		}
	})

	t.Run("ParseCryptoAddressType parses correctly", func(t *testing.T) {
		t.Parallel()
		if got := ParseCryptoAddressType("btc_legacy"); got != CryptoAddressTypeBTCLegacy {
			t.Errorf("expected btc_legacy, got %v", got)
		}
		if got := ParseCryptoAddressType("legacy"); got != CryptoAddressTypeBTCLegacy {
			t.Errorf("expected btc_legacy for legacy, got %v", got)
		}
		if got := ParseCryptoAddressType("invalid"); got != CryptoAddressTypeUnknown {
			t.Errorf("expected unknown, got %v", got)
		}
	})
}

func TestAWSResourceType(t *testing.T) {
	t.Parallel()

	t.Run("String returns correct value", func(t *testing.T) {
		t.Parallel()
		if got := AWSResourceTypeS3.String(); got != "s3" {
			t.Errorf("expected s3, got %s", got)
		}
		if got := AWSResourceTypeUnknown.String(); got != "unknown" {
			t.Errorf("expected unknown, got %s", got)
		}
	})

	t.Run("IsValid returns true for known types", func(t *testing.T) {
		t.Parallel()
		if !AWSResourceTypeS3.IsValid() {
			t.Error("expected s3 to be valid")
		}
		if AWSResourceTypeUnknown.IsValid() {
			t.Error("expected unknown to be invalid")
		}
	})

	t.Run("ParseAWSResourceType parses correctly", func(t *testing.T) {
		t.Parallel()
		if got := ParseAWSResourceType("s3"); got != AWSResourceTypeS3 {
			t.Errorf("expected s3, got %v", got)
		}
		if got := ParseAWSResourceType("cloudfront"); got != AWSResourceTypeCloudFront {
			t.Errorf("expected cloudfront, got %v", got)
		}
		if got := ParseAWSResourceType("invalid"); got != AWSResourceTypeUnknown {
			t.Errorf("expected unknown, got %v", got)
		}
	})
}

func TestPlatformVariants(t *testing.T) {
	t.Parallel()

	t.Run("social platforms", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			input    string
			platform SocialPlatform
			severity Severity
		}{
			{"twitter", SocialPlatformTwitter, SeverityHigh},
			{"github", SocialPlatformGitHub, SeverityHigh},
			{"telegram", SocialPlatformTelegram, SeverityMedium},
			{"reddit", SocialPlatformReddit, SeverityMedium},
			{"matrix", SocialPlatformMatrix, SeverityLow},
			{"signal", SocialPlatformSignal, SeverityLow},
			{"session", SocialPlatformSession, SeverityLow},
			{"dread", SocialPlatformDread, SeverityLow},
			{"linkedin", SocialPlatformLinkedIn, SeverityCritical},
			{"facebook", SocialPlatformFacebook, SeverityCritical},
			{"instagram", SocialPlatformInstagram, SeverityHigh},
			{"youtube", SocialPlatformYouTube, SeverityHigh},
			{"discord", SocialPlatformDiscord, SeverityMedium},
			{"keybase", SocialPlatformKeybase, SeverityHigh},
			{"mastodon", SocialPlatformMastodon, SeverityMedium},
		}

		for _, tt := range tests {
			got := ParseSocialPlatform(tt.input)
			if got != tt.platform {
				t.Errorf("ParseSocialPlatform(%q) = %q, want %q", tt.input, got, tt.platform)
			}
			if !got.IsValid() {
				t.Errorf("expected %q to be valid", got)
			}
			if got.String() != tt.input {
				t.Errorf("String() = %q, want %q", got.String(), tt.input)
			}
			if got.DefaultSeverity() != tt.severity {
				t.Errorf("DefaultSeverity(%q) = %q, want %q", got, got.DefaultSeverity(), tt.severity)
			}
		}
		if SocialPlatformUnknown.DefaultSeverity() != SeverityMedium {
			t.Error("unexpected fallback social severity")
		}
	})

	t.Run("analytics platforms", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			input      string
			platform   AnalyticsPlatform
			severity   Severity
			cloudBased bool
		}{
			{"ga4", AnalyticsPlatformGA4, SeverityCritical, true},
			{"ua", AnalyticsPlatformUA, SeverityCritical, true},
			{"meta_pixel", AnalyticsPlatformMetaPixel, SeverityCritical, true},
			{"matomo", AnalyticsPlatformMatomo, SeverityMedium, false},
			{"clarity", AnalyticsPlatformClarity, SeverityHigh, true},
			{"hotjar", AnalyticsPlatformHotjar, SeverityHigh, true},
			{"plausible", AnalyticsPlatformPlausible, SeverityMedium, false},
			{"mixpanel", AnalyticsPlatformMixpanel, SeverityHigh, true},
			{"segment", AnalyticsPlatformSegment, SeverityHigh, true},
			{"amplitude", AnalyticsPlatformAmplitude, SeverityHigh, true},
			{"heap", AnalyticsPlatformHeap, SeverityHigh, true},
		}

		for _, tt := range tests {
			got := ParseAnalyticsPlatform(tt.input)
			if got != tt.platform || !got.IsValid() || got.String() != tt.input {
				t.Errorf("analytics platform round trip failed for %q: got %q", tt.input, got)
			}
			if got.DefaultSeverity() != tt.severity {
				t.Errorf("DefaultSeverity(%q) = %q, want %q", got, got.DefaultSeverity(), tt.severity)
			}
			if got.IsCloudBased() != tt.cloudBased {
				t.Errorf("IsCloudBased(%q) = %v, want %v", got, got.IsCloudBased(), tt.cloudBased)
			}
		}
		if AnalyticsPlatformUnknown.DefaultSeverity() != SeverityHigh {
			t.Error("unexpected fallback analytics severity")
		}
	})

	t.Run("API detection methods", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			input  string
			method APIDetectionMethod
		}{
			{"fetch", APIDetectionFetch},
			{"axios", APIDetectionAxios},
			{"xhr", APIDetectionXHR},
			{"websocket", APIDetectionWebSocket},
			{"graphql", APIDetectionGraphQL},
			{"swagger", APIDetectionSwagger},
			{"eventsource", APIDetectionEventSource},
		}

		for _, tt := range tests {
			got := ParseAPIDetectionMethod(tt.input)
			if got != tt.method || !got.IsValid() || got.String() != tt.input {
				t.Errorf("API detection round trip failed for %q: got %q", tt.input, got)
			}
		}
	})

	t.Run("cryptocurrency address types", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			input    string
			kind     CryptoAddressType
			currency string
			severity Severity
		}{
			{"btc_legacy", CryptoAddressTypeBTCLegacy, "Bitcoin", SeverityHigh},
			{"btc_p2sh", CryptoAddressTypeBTCP2SH, "Bitcoin", SeverityHigh},
			{"btc_bech32", CryptoAddressTypeBTCBech32, "Bitcoin", SeverityHigh},
			{"btc_taproot", CryptoAddressTypeBTCTaproot, "Bitcoin", SeverityHigh},
			{"eth", CryptoAddressTypeETH, "Ethereum", SeverityHigh},
			{"xmr_standard", CryptoAddressTypeXMRStandard, "Monero", SeverityMedium},
			{"xmr_integrated", CryptoAddressTypeXMRIntegrated, "Monero", SeverityMedium},
			{"xmr_subaddress", CryptoAddressTypeXMRSubaddress, "Monero", SeverityMedium},
			{"ltc", CryptoAddressTypeLTC, "Litecoin", SeverityHigh},
			{"doge", CryptoAddressTypeDOGE, "Dogecoin", SeverityHigh},
			{"dash", CryptoAddressTypeDASH, "Dash", SeverityHigh},
			{"zec", CryptoAddressTypeZEC, "Zcash", SeverityHigh},
		}

		for _, tt := range tests {
			got := ParseCryptoAddressType(tt.input)
			if got != tt.kind || !got.IsValid() || got.String() != tt.input {
				t.Errorf("cryptocurrency type round trip failed for %q: got %q", tt.input, got)
			}
			if got.Currency() != tt.currency {
				t.Errorf("Currency(%q) = %q, want %q", got, got.Currency(), tt.currency)
			}
			if got.DefaultSeverity() != tt.severity {
				t.Errorf("DefaultSeverity(%q) = %q, want %q", got, got.DefaultSeverity(), tt.severity)
			}
		}
		if CryptoAddressTypeUnknown.Currency() != "Unknown" {
			t.Error("unexpected fallback currency")
		}
		if CryptoAddressTypeUnknown.DefaultSeverity() != SeverityHigh {
			t.Error("unexpected fallback cryptocurrency severity")
		}
	})

	t.Run("AWS resource types", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			input string
			kind  AWSResourceType
		}{
			{"s3", AWSResourceTypeS3},
			{"cloudfront", AWSResourceTypeCloudFront},
			{"apigateway", AWSResourceTypeAPIGateway},
			{"lambda", AWSResourceTypeLambda},
			{"ec2", AWSResourceTypeEC2},
		}

		for _, tt := range tests {
			got := ParseAWSResourceType(tt.input)
			if got != tt.kind || !got.IsValid() || got.String() != tt.input {
				t.Errorf("AWS resource round trip failed for %q: got %q", tt.input, got)
			}
		}
	})
}
