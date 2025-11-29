package model

import (
	"errors"
	"testing"
)

// testOnionV3Addr1 is a valid v3 address generated from an all-zero 32-byte public key.
// It is for testing purposes only and does not correspond to any real hidden service.
const testOnionV3Addr1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion"

func TestNewOnionAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		address     string
		wantVersion OnionVersion
		wantErr     error
	}{
		{
			name:        "valid v3 address with suffix",
			address:     testOnionV3Addr1,
			wantVersion: OnionVersionV3,
			wantErr:     nil,
		},
		{
			name:        "valid v3 address without suffix",
			address:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd",
			wantVersion: OnionVersionV3,
			wantErr:     nil,
		},
		{
			name:        "valid v2 address with suffix",
			address:     "3g2upl4pq6kufc4m.onion",
			wantVersion: OnionVersionV2,
			wantErr:     nil,
		},
		{
			name:        "valid v2 address without suffix",
			address:     "3g2upl4pq6kufc4m",
			wantVersion: OnionVersionV2,
			wantErr:     nil,
		},
		{
			name:        "uppercase address should be normalized",
			address:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM2DQD.ONION",
			wantVersion: OnionVersionV3,
			wantErr:     nil,
		},
		{
			name:        "empty address",
			address:     "",
			wantVersion: OnionVersionUnknown,
			wantErr:     ErrEmptyOnionAddress,
		},
		{
			name:        "invalid address - wrong length",
			address:     "invalid.onion",
			wantVersion: OnionVersionUnknown,
			wantErr:     ErrInvalidOnionAddress,
		},
		{
			name:        "invalid address - contains invalid characters (digit 1)",
			address:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam1dqd.onion",
			wantVersion: OnionVersionUnknown,
			wantErr:     ErrInvalidOnionAddress,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			oa, err := NewOnionAddress(tt.address)

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.wantErr)
				} else if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if oa.Version() != tt.wantVersion {
				t.Errorf("expected version %v, got %v", tt.wantVersion, oa.Version())
			}
		})
	}
}

func TestOnionAddress_Methods(t *testing.T) {
	t.Parallel()

	v3, _ := NewOnionAddress(testOnionV3Addr1)
	v2, _ := NewOnionAddress("3g2upl4pq6kufc4m.onion")

	t.Run("String returns full address", func(t *testing.T) {
		t.Parallel()
		if got := v3.String(); got != testOnionV3Addr1 {
			t.Errorf("expected full address, got %s", got)
		}
	})

	t.Run("Base returns address without suffix", func(t *testing.T) {
		t.Parallel()
		expected := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd"
		if got := v3.Base(); got != expected {
			t.Errorf("expected base address, got %s", got)
		}
	})

	t.Run("IsV3 returns true for v3", func(t *testing.T) {
		t.Parallel()
		if !v3.IsV3() {
			t.Error("expected IsV3 to be true")
		}
		if v3.IsV2() {
			t.Error("expected IsV2 to be false")
		}
	})

	t.Run("IsV2 returns true for v2", func(t *testing.T) {
		t.Parallel()
		if !v2.IsV2() {
			t.Error("expected IsV2 to be true")
		}
		if v2.IsV3() {
			t.Error("expected IsV3 to be false")
		}
	})

	t.Run("IsDeprecated returns true for v2", func(t *testing.T) {
		t.Parallel()
		if !v2.IsDeprecated() {
			t.Error("expected v2 to be deprecated")
		}
		if v3.IsDeprecated() {
			t.Error("expected v3 to not be deprecated")
		}
	})

	t.Run("Equals compares addresses", func(t *testing.T) {
		t.Parallel()
		v3Copy, _ := NewOnionAddress(testOnionV3Addr1)
		if !v3.Equals(v3Copy) {
			t.Error("expected addresses to be equal")
		}
		if v3.Equals(v2) {
			t.Error("expected addresses to be different")
		}
	})

	t.Run("IsZero returns true for zero value", func(t *testing.T) {
		t.Parallel()
		var zero OnionAddress
		if !zero.IsZero() {
			t.Error("expected zero value to be zero")
		}
		if v3.IsZero() {
			t.Error("expected non-zero value to not be zero")
		}
	})
}

func TestOnionAddress_ToOnionLink(t *testing.T) {
	t.Parallel()

	v3, _ := NewOnionAddress(testOnionV3Addr1)
	link := v3.ToOnionLink("found in page content")

	if link.Address != v3.String() {
		t.Errorf("expected address %s, got %s", v3.String(), link.Address)
	}
	if link.Version != 3 {
		t.Errorf("expected version 3, got %d", link.Version)
	}
	if link.Deprecated {
		t.Error("expected deprecated to be false")
	}
	if link.Context != "found in page content" {
		t.Errorf("expected context, got %s", link.Context)
	}
}

func TestParseOnionAddressFromURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		url    string
		wantOk bool
		wantV3 bool
	}{
		{
			name:   "http URL with v3 address",
			url:    "http://" + testOnionV3Addr1 + "/search",
			wantOk: true,
			wantV3: true,
		},
		{
			name:   "https URL with v2 address",
			url:    "https://3g2upl4pq6kufc4m.onion/",
			wantOk: true,
			wantV3: false,
		},
		{
			name:   "no onion address",
			url:    "https://example.com/",
			wantOk: false,
		},
		{
			name:   "invalid onion address in URL",
			url:    "http://invalid.onion/",
			wantOk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			oa, ok := ParseOnionAddressFromURL(tt.url)
			if ok != tt.wantOk {
				t.Errorf("expected ok=%v, got %v", tt.wantOk, ok)
			}
			if tt.wantOk && tt.wantV3 && !oa.IsV3() {
				t.Error("expected v3 address")
			}
			if tt.wantOk && !tt.wantV3 && !oa.IsV2() {
				t.Error("expected v2 address")
			}
		})
	}
}

func TestOnionVersion_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version OnionVersion
		want    string
	}{
		{OnionVersionV2, "v2"},
		{OnionVersionV3, "v3"},
		{OnionVersionUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.version.String(); got != tt.want {
				t.Errorf("expected %s, got %s", tt.want, got)
			}
		})
	}
}

func TestMustNewOnionAddress(t *testing.T) {
	t.Parallel()

	t.Run("valid address does not panic", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("unexpected panic: %v", r)
			}
		}()
		_ = MustNewOnionAddress(testOnionV3Addr1)
	})

	t.Run("invalid address panics", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for invalid address")
			}
		}()
		_ = MustNewOnionAddress("invalid")
	})
}
