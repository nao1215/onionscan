package model

import (
	"errors"
	"strings"
)

// OnionAddress errors.
var (
	// ErrInvalidOnionAddress is returned when the address format is invalid.
	ErrInvalidOnionAddress = errors.New("invalid onion address format")
	// ErrEmptyOnionAddress is returned when the address is empty.
	ErrEmptyOnionAddress = errors.New("onion address cannot be empty")
)

// OnionVersion represents the version of an onion address.
type OnionVersion int

const (
	// OnionVersionUnknown indicates an unknown or invalid version.
	OnionVersionUnknown OnionVersion = 0
	// OnionVersionV2 indicates a v2 onion address (16 characters, deprecated).
	OnionVersionV2 OnionVersion = 2
	// OnionVersionV3 indicates a v3 onion address (56 characters, ed25519).
	OnionVersionV3 OnionVersion = 3
)

const (
	// onionSuffix is the .onion TLD suffix.
	onionSuffix = ".onion"
	// v2AddressLength is the length of a v2 onion address (without .onion).
	v2AddressLength = 16
	// v3AddressLength is the length of a v3 onion address (without .onion).
	v3AddressLength = 56
	// unknownStr is the string representation for unknown values.
	unknownStr = "unknown"
)

// String returns the string representation of the OnionVersion.
func (v OnionVersion) String() string {
	switch v {
	case OnionVersionV2:
		return "v2"
	case OnionVersionV3:
		return "v3"
	default:
		return unknownStr
	}
}

// OnionAddress is an immutable value object representing a Tor hidden service address.
// It validates the address format and provides version detection.
type OnionAddress struct {
	address string       // Full address including .onion suffix
	version OnionVersion // Detected version (v2 or v3)
}

// NewOnionAddress creates a new OnionAddress from a string.
// It validates the address format and detects the version.
// Returns an error if the address is invalid.
func NewOnionAddress(address string) (OnionAddress, error) {
	if address == "" {
		return OnionAddress{}, ErrEmptyOnionAddress
	}

	// Normalize: lowercase and ensure .onion suffix
	normalized := strings.ToLower(strings.TrimSpace(address))
	if !strings.HasSuffix(normalized, onionSuffix) {
		normalized += onionSuffix
	}

	// Extract the base address (without .onion)
	base := strings.TrimSuffix(normalized, onionSuffix)

	// Validate and detect version
	version := detectOnionVersion(base)
	if version == OnionVersionUnknown {
		return OnionAddress{}, ErrInvalidOnionAddress
	}

	return OnionAddress{
		address: normalized,
		version: version,
	}, nil
}

// MustNewOnionAddress creates a new OnionAddress or panics if invalid.
// Use only for known-valid addresses in tests or initialization.
func MustNewOnionAddress(address string) OnionAddress {
	oa, err := NewOnionAddress(address)
	if err != nil {
		panic(err)
	}
	return oa
}

// detectOnionVersion determines the onion address version based on length and characters.
func detectOnionVersion(base string) OnionVersion {
	switch len(base) {
	case v2AddressLength:
		// V2: 16 characters, base32 (a-z, 2-7)
		if isValidBase32(base) {
			return OnionVersionV2
		}
	case v3AddressLength:
		// V3: 56 characters, base32
		if isValidBase32(base) {
			return OnionVersionV3
		}
	}
	return OnionVersionUnknown
}

// isValidBase32 checks if a string contains only valid base32 characters.
func isValidBase32(s string) bool {
	for _, c := range s {
		isLowerLetter := c >= 'a' && c <= 'z'
		isBase32Digit := c >= '2' && c <= '7'
		if !isLowerLetter && !isBase32Digit {
			return false
		}
	}
	return true
}

// String returns the full onion address including .onion suffix.
func (o OnionAddress) String() string {
	return o.address
}

// Base returns the onion address without the .onion suffix.
func (o OnionAddress) Base() string {
	return strings.TrimSuffix(o.address, onionSuffix)
}

// Version returns the onion address version.
func (o OnionAddress) Version() OnionVersion {
	return o.version
}

// IsV2 returns true if this is a v2 onion address.
func (o OnionAddress) IsV2() bool {
	return o.version == OnionVersionV2
}

// IsV3 returns true if this is a v3 onion address.
func (o OnionAddress) IsV3() bool {
	return o.version == OnionVersionV3
}

// IsDeprecated returns true if this address uses a deprecated version (v2).
// V2 addresses were deprecated in October 2021.
func (o OnionAddress) IsDeprecated() bool {
	return o.version == OnionVersionV2
}

// IsZero returns true if this is a zero value (empty) OnionAddress.
func (o OnionAddress) IsZero() bool {
	return o.address == ""
}

// Equals returns true if two OnionAddress values are equal.
func (o OnionAddress) Equals(other OnionAddress) bool {
	return o.address == other.address
}

// ToOnionLink converts the OnionAddress to an OnionLink with the given context.
func (o OnionAddress) ToOnionLink(context string) OnionLink {
	return OnionLink{
		Address:    o.address,
		Version:    int(o.version),
		Deprecated: o.IsDeprecated(),
		Context:    context,
	}
}

// ParseOnionAddressFromURL extracts an onion address from a URL string.
// Returns the OnionAddress and true if found, or zero value and false if not.
func ParseOnionAddressFromURL(url string) (OnionAddress, bool) {
	// Simple extraction - look for .onion in the URL
	lower := strings.ToLower(url)
	idx := strings.Index(lower, onionSuffix)
	if idx == -1 {
		return OnionAddress{}, false
	}

	// Find the start of the address (scan backwards for non-alphanumeric)
	start := idx
	for start > 0 {
		c := lower[start-1]
		isLowerLetter := c >= 'a' && c <= 'z'
		isBase32Digit := c >= '2' && c <= '7'
		if !isLowerLetter && !isBase32Digit {
			break
		}
		start--
	}

	address := lower[start : idx+len(onionSuffix)]
	oa, err := NewOnionAddress(address)
	if err != nil {
		return OnionAddress{}, false
	}
	return oa, true
}
