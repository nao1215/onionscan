package tor

import (
	"errors"
	"strings"
	"testing"
)

// Test v3 onion addresses - these are valid addresses generated from deterministic public keys
// for testing purposes only. They do not correspond to any real hidden services.
const (
	// testOnionV3Addr1 is generated from an all-zero 32-byte public key
	testOnionV3Addr1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion"
	// testOnionV3Addr2 is generated from a sequential (0,1,2,...,31) public key
	testOnionV3Addr2 = "aaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dyp3kead.onion"
)

// TestIsValidV3Address tests v3 onion address validation.
// Test addresses are generated using the v3 address format specification.
func TestIsValidV3Address(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		address  string
		expected bool
	}{
		{
			name: "valid v3 address (test address)",
			// This is a valid v3 onion address for testing
			address:  testOnionV3Addr1,
			expected: true,
		},
		{
			name:     "valid v3 address uppercase should match after normalization",
			address:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM2DQD.onion",
			expected: true,
		},
		{
			name:     "v2 address (16 chars) should be invalid",
			address:  "facebookcorewwwi.onion",
			expected: false,
		},
		{
			name:     "too short address",
			address:  "abc.onion",
			expected: false,
		},
		{
			name:     "too long address",
			address:  strings.Repeat("a", 57) + ".onion",
			expected: false,
		},
		{
			name:     "missing .onion suffix",
			address:  strings.Repeat("a", 56),
			expected: false,
		},
		{
			name:     "invalid characters (contains 0)",
			address:  strings.Repeat("0", 56) + ".onion",
			expected: false,
		},
		{
			name:     "invalid characters (contains 1)",
			address:  strings.Repeat("1", 56) + ".onion",
			expected: false,
		},
		{
			name:     "invalid characters (contains 8)",
			address:  strings.Repeat("8", 56) + ".onion",
			expected: false,
		},
		{
			name:     "empty string",
			address:  "",
			expected: false,
		},
		{
			name:     "only .onion suffix",
			address:  ".onion",
			expected: false,
		},
		{
			name: "wrong checksum (modified last char)",
			// Take a valid address and modify it slightly to break checksum
			address:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqe.onion",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := IsValidV3Address(tc.address)
			if result != tc.expected {
				t.Errorf("IsValidV3Address(%q) = %v, expected %v", tc.address, result, tc.expected)
			}
		})
	}
}

// TestIsV2Address tests detection of deprecated v2 onion addresses.
func TestIsV2Address(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		address  string
		expected bool
	}{
		{
			name:     "valid v2 address format",
			address:  "facebookcorewwwi.onion",
			expected: true,
		},
		{
			name:     "v2 address uppercase",
			address:  "FACEBOOKCOREWWWI.onion",
			expected: true,
		},
		{
			name:     "v3 address should not match v2",
			address:  testOnionV3Addr1,
			expected: false,
		},
		{
			name:     "too short for v2",
			address:  "abc.onion",
			expected: false,
		},
		{
			name:     "too long for v2",
			address:  strings.Repeat("a", 17) + ".onion",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := IsV2Address(tc.address)
			if result != tc.expected {
				t.Errorf("IsV2Address(%q) = %v, expected %v", tc.address, result, tc.expected)
			}
		})
	}
}

// TestExtractV3Addresses tests extraction of v3 addresses from text content.
func TestExtractV3Addresses(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		content       string
		expectedCount int
	}{
		{
			name:          "single address in text",
			content:       "Visit us at " + testOnionV3Addr1,
			expectedCount: 1,
		},
		{
			name:          "multiple different addresses",
			content:       "Link1: " + testOnionV3Addr1 + " Link2: " + testOnionV3Addr2,
			expectedCount: 2,
		},
		{
			name:          "duplicate addresses should be deduplicated",
			content:       testOnionV3Addr1 + " and again " + testOnionV3Addr1,
			expectedCount: 1,
		},
		{
			name:          "no addresses",
			content:       "This is just regular text without any onion addresses.",
			expectedCount: 0,
		},
		{
			name:          "v2 address should not be extracted",
			content:       "Old address: facebookcorewwwi.onion",
			expectedCount: 0,
		},
		{
			name:          "mixed v2 and v3 should only extract v3",
			content:       "Old: facebookcorewwwi.onion New: " + testOnionV3Addr1,
			expectedCount: 1,
		},
		{
			name:          "empty content",
			content:       "",
			expectedCount: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := ExtractV3Addresses(tc.content)
			if len(result) != tc.expectedCount {
				t.Errorf("ExtractV3Addresses() returned %d addresses, expected %d", len(result), tc.expectedCount)
			}
		})
	}
}

// TestExtractV2Addresses tests extraction of deprecated v2 addresses from text.
func TestExtractV2Addresses(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		content       string
		expectedCount int
	}{
		{
			name:          "single v2 address",
			content:       "Old site: facebookcorewwwi.onion",
			expectedCount: 1,
		},
		{
			name:          "v3 address should not be extracted",
			content:       "New: " + testOnionV3Addr1,
			expectedCount: 0,
		},
		{
			name:          "duplicate v2 addresses should be deduplicated",
			content:       "facebookcorewwwi.onion and facebookcorewwwi.onion",
			expectedCount: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := ExtractV2Addresses(tc.content)
			if len(result) != tc.expectedCount {
				t.Errorf("ExtractV2Addresses() returned %d addresses, expected %d", len(result), tc.expectedCount)
			}
		})
	}
}

// TestNormalizeAddress tests address normalization.
func TestNormalizeAddress(t *testing.T) {
	t.Parallel()

	t.Run("valid address is returned unchanged (except case)", func(t *testing.T) {
		t.Parallel()
		input := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM2DQD.onion"
		expected := testOnionV3Addr1

		result, err := NormalizeAddress(input)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result != expected {
			t.Errorf("got %q, expected %q", result, expected)
		}
	})

	t.Run("address without .onion suffix gets it added", func(t *testing.T) {
		t.Parallel()
		input := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd"
		expected := testOnionV3Addr1

		result, err := NormalizeAddress(input)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result != expected {
			t.Errorf("got %q, expected %q", result, expected)
		}
	})

	t.Run("whitespace is trimmed", func(t *testing.T) {
		t.Parallel()
		input := "  " + testOnionV3Addr1 + "  \n"
		expected := testOnionV3Addr1

		result, err := NormalizeAddress(input)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result != expected {
			t.Errorf("got %q, expected %q", result, expected)
		}
	})

	t.Run("invalid address returns error", func(t *testing.T) {
		t.Parallel()
		input := "invalid"

		_, err := NormalizeAddress(input)
		if err == nil {
			t.Error("expected error, got nil")
		}
		if !errors.Is(err, ErrInvalidOnionAddress) {
			t.Errorf("expected ErrInvalidOnionAddress, got %v", err)
		}
	})

	t.Run("v2 address returns deprecated error", func(t *testing.T) {
		t.Parallel()
		input := "facebookcorewwwi.onion"

		_, err := NormalizeAddress(input)
		if err == nil {
			t.Error("expected error, got nil")
		}
		if !errors.Is(err, ErrV2AddressDeprecated) {
			t.Errorf("expected ErrV2AddressDeprecated, got %v", err)
		}
	})

	t.Run("https URL scheme is stripped", func(t *testing.T) {
		t.Parallel()
		input := "https://" + testOnionV3Addr1
		expected := testOnionV3Addr1

		result, err := NormalizeAddress(input)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result != expected {
			t.Errorf("got %q, expected %q", result, expected)
		}
	})

	t.Run("http URL scheme is stripped", func(t *testing.T) {
		t.Parallel()
		input := "http://" + testOnionV3Addr1
		expected := testOnionV3Addr1

		result, err := NormalizeAddress(input)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result != expected {
			t.Errorf("got %q, expected %q", result, expected)
		}
	})

	t.Run("URL with path is handled", func(t *testing.T) {
		t.Parallel()
		input := "https://" + testOnionV3Addr1 + "/search?q=test"
		expected := testOnionV3Addr1

		result, err := NormalizeAddress(input)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result != expected {
			t.Errorf("got %q, expected %q", result, expected)
		}
	})
}

// TestComputeV3AddressFromPublicKey tests address computation from public key.
func TestComputeV3AddressFromPublicKey(t *testing.T) {
	t.Parallel()

	t.Run("invalid public key length returns error", func(t *testing.T) {
		t.Parallel()

		// Test various invalid lengths
		invalidLengths := []int{0, 16, 31, 33, 64}

		for _, length := range invalidLengths {
			pubkey := make([]byte, length)
			_, err := ComputeV3AddressFromPublicKey(pubkey)
			if err == nil {
				t.Errorf("expected error for pubkey length %d, got nil", length)
			}
		}
	})

	t.Run("valid public key produces valid address", func(t *testing.T) {
		t.Parallel()

		// Create a 32-byte public key (all zeros for testing)
		pubkey := make([]byte, 32)

		address, err := ComputeV3AddressFromPublicKey(pubkey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// The result should be a valid v3 address
		if !IsValidV3Address(address) {
			t.Errorf("computed address %q is not valid", address)
		}

		// Should have correct length
		if len(address) != OnionV3TotalLength {
			t.Errorf("address length = %d, expected %d", len(address), OnionV3TotalLength)
		}
	})
}

// TestProxyStatusString tests the String method of ProxyStatus.
func TestProxyStatusString(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		status   ProxyStatus
		expected string
	}{
		{ProxyStatusOK, "OK"},
		{ProxyStatusWrongType, "wrong type (not Tor)"},
		{ProxyStatusCannotConnect, "cannot connect"},
		{ProxyStatusTimeout, "timeout"},
		{ProxyStatus(999), "unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			t.Parallel()
			if tc.status.String() != tc.expected {
				t.Errorf("got %q, expected %q", tc.status.String(), tc.expected)
			}
		})
	}
}

// TestProxyStatusError tests the Error method of ProxyStatus.
func TestProxyStatusError(t *testing.T) {
	t.Parallel()

	t.Run("OK returns nil", func(t *testing.T) {
		t.Parallel()
		if err := ProxyStatusOK.Error(); err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("WrongType returns ErrProxyNotTor", func(t *testing.T) {
		t.Parallel()
		if !errors.Is(ProxyStatusWrongType.Error(), ErrProxyNotTor) {
			t.Error("expected ErrProxyNotTor")
		}
	})

	t.Run("CannotConnect returns ErrProxyCannotConnect", func(t *testing.T) {
		t.Parallel()
		if !errors.Is(ProxyStatusCannotConnect.Error(), ErrProxyCannotConnect) {
			t.Error("expected ErrProxyCannotConnect")
		}
	})

	t.Run("Timeout returns ErrProxyTimeout", func(t *testing.T) {
		t.Parallel()
		if !errors.Is(ProxyStatusTimeout.Error(), ErrProxyTimeout) {
			t.Error("expected ErrProxyTimeout")
		}
	})
}

// TestOnionError tests the onionError type.
func TestOnionError(t *testing.T) {
	t.Parallel()

	t.Run("newOnionError creates error with message", func(t *testing.T) {
		t.Parallel()

		err := newOnionError("test error message")
		if err == nil {
			t.Fatal("expected non-nil error")
		}
		if err.Error() != "test error message" {
			t.Errorf("expected 'test error message', got %q", err.Error())
		}
	})

	t.Run("error implements error interface", func(t *testing.T) {
		t.Parallel()

		var err error = newOnionError("interface test")
		if err.Error() != "interface test" {
			t.Errorf("expected 'interface test', got %q", err.Error())
		}
	})
}
