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
