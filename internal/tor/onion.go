package tor

import (
	"encoding/base32"
	"regexp"
	"strings"

	"golang.org/x/crypto/sha3"
)

// Onion address constants.
const (
	// OnionV3Length is the length of a v3 onion address without the ".onion" suffix.
	// V3 addresses are 56 characters of base32-encoded data.
	OnionV3Length = 56

	// OnionV3TotalLength is the total length including the ".onion" suffix.
	OnionV3TotalLength = 62

	// OnionV3Version is the version byte for v3 onion addresses.
	OnionV3Version = 0x03

	// OnionV2Length is the length of a v2 onion address without the ".onion" suffix.
	// V2 addresses are 16 characters. Note: V2 was deprecated in 2021.
	OnionV2Length = 16

	// OnionSuffix is the common suffix for all onion addresses.
	OnionSuffix = ".onion"
)

// onionV3Pattern matches v3 onion addresses (56 base32 characters + .onion).
// Base32 uses lowercase a-z and digits 2-7 (no 0, 1, 8, 9 to avoid confusion).
var onionV3Pattern = regexp.MustCompile(`^[a-z2-7]{56}\.onion$`)

// onionV2Pattern matches v2 onion addresses (16 base32 characters + .onion).
// These are deprecated but we detect them to warn users.
var onionV2Pattern = regexp.MustCompile(`^[a-z2-7]{16}\.onion$`)

// onionV3ContentPattern matches v3 addresses within larger text content.
var onionV3ContentPattern = regexp.MustCompile(`[a-z2-7]{56}\.onion`)

// onionV2ContentPattern matches v2 addresses within larger text content.
// We use a negative lookahead pattern equivalent: match 16 chars followed by .onion
// but NOT preceded by additional base32 characters (which would indicate a v3 address).
// Since Go's regexp doesn't support lookahead, we need to filter results in code.
var onionV2ContentPattern = regexp.MustCompile(`[a-z2-7]{16}\.onion`)

// checksumPrefix is the prefix used in v3 onion address checksum calculation.
// This is specified in the Tor rendezvous specification.
var checksumPrefix = []byte(".onion checksum")

// IsValidV3Address checks if the given address is a valid v3 onion address.
// It performs both format validation and checksum verification.
//
// Design decision: We perform full checksum validation rather than just
// pattern matching because:
// 1. It catches typos and corrupted addresses
// 2. It verifies the address was properly generated
// 3. It matches what Tor itself does when connecting
//
// The address should be lowercase and include the ".onion" suffix.
func IsValidV3Address(address string) bool {
	// Normalize to lowercase
	address = strings.ToLower(address)

	// Check basic format with regex
	if !onionV3Pattern.MatchString(address) {
		return false
	}

	// Extract the base32-encoded part (without .onion suffix)
	onionPart := strings.TrimSuffix(address, OnionSuffix)

	// Decode from base32
	// The Tor spec uses standard base32 encoding (RFC 4648)
	decoded, err := base32.StdEncoding.DecodeString(strings.ToUpper(onionPart))
	if err != nil {
		return false
	}

	// Decoded data should be exactly 35 bytes:
	// - 32 bytes: ed25519 public key
	// - 2 bytes: checksum
	// - 1 byte: version
	if len(decoded) != 35 {
		return false
	}

	pubkey := decoded[:32]
	checksum := decoded[32:34]
	version := decoded[34]

	// Verify version is 0x03 (v3)
	if version != OnionV3Version {
		return false
	}

	// Verify checksum
	// Checksum = first 2 bytes of SHA3-256(".onion checksum" || pubkey || version)
	expectedChecksum := computeV3Checksum(pubkey, version)

	return checksum[0] == expectedChecksum[0] && checksum[1] == expectedChecksum[1]
}

// computeV3Checksum computes the checksum bytes for a v3 onion address.
// The checksum is the first 2 bytes of SHA3-256(".onion checksum" || pubkey || version).
func computeV3Checksum(pubkey []byte, version byte) []byte {
	// Construct the data to hash
	data := make([]byte, 0, len(checksumPrefix)+len(pubkey)+1)
	data = append(data, checksumPrefix...)
	data = append(data, pubkey...)
	data = append(data, version)

	// Compute SHA3-256 hash
	hash := sha3.Sum256(data)

	// Return first 2 bytes as checksum
	return hash[:2]
}

// IsV2Address checks if the given address matches the v2 onion address format.
// V2 addresses were deprecated in October 2021 and no longer work on the Tor network.
//
// This function is provided to detect and warn about v2 addresses in content,
// not to validate them for use.
func IsV2Address(address string) bool {
	return onionV2Pattern.MatchString(strings.ToLower(address))
}

// ExtractV3Addresses finds all v3 onion addresses in the given text.
// Returns a deduplicated slice of addresses found.
//
// Design decision: We deduplicate results because the same address often
// appears multiple times in page content (links, text, etc.). Returning
// unique addresses simplifies processing for callers.
func ExtractV3Addresses(content string) []string {
	content = strings.ToLower(content)
	matches := onionV3ContentPattern.FindAllString(content, -1)

	// Deduplicate using a map
	seen := make(map[string]bool)
	var result []string

	for _, match := range matches {
		if !seen[match] {
			seen[match] = true
			result = append(result, match)
		}
	}

	return result
}

// ExtractV2Addresses finds all v2 onion addresses in the given text.
// Returns a deduplicated slice of addresses found.
//
// These addresses are deprecated and non-functional, but detecting them
// is useful for reporting outdated content.
//
// Design decision: We first extract all v3 addresses, then filter v2 matches
// to exclude any that are substrings of v3 addresses. This is necessary because
// the last 16 characters of a v3 address would otherwise match the v2 pattern.
func ExtractV2Addresses(content string) []string {
	content = strings.ToLower(content)

	// First, find all v3 addresses to exclude their substrings
	v3Addresses := make(map[string]bool)
	for _, v3 := range onionV3ContentPattern.FindAllString(content, -1) {
		v3Addresses[v3] = true
	}

	matches := onionV2ContentPattern.FindAllStringIndex(content, -1)

	// Deduplicate using a map
	seen := make(map[string]bool)
	var result []string

	for _, matchIdx := range matches {
		match := content[matchIdx[0]:matchIdx[1]]

		// Skip if this match is part of a v3 address
		// Check if there's a v3 address that ends at the same position
		isPartOfV3 := false
		for v3Addr := range v3Addresses {
			// Check if the v2 match is a suffix of this v3 address
			if strings.HasSuffix(v3Addr, match) {
				// Verify the positions overlap
				v3Start := strings.Index(content, v3Addr)
				if v3Start != -1 && v3Start+len(v3Addr) == matchIdx[1] {
					isPartOfV3 = true
					break
				}
			}
		}

		if isPartOfV3 {
			continue
		}

		if !seen[match] {
			seen[match] = true
			result = append(result, match)
		}
	}

	return result
}

// NormalizeAddress normalizes an onion address to lowercase with .onion suffix.
// Returns the normalized address or an error if invalid.
//
// This function handles common input variations:
// - Uppercase letters
// - Missing .onion suffix
// - Extra whitespace
// - URL schemes (http://, https://)
// - Trailing paths or query strings
func NormalizeAddress(address string) (string, error) {
	// Trim whitespace and convert to lowercase
	address = strings.ToLower(strings.TrimSpace(address))

	// Strip URL scheme if present
	address = strings.TrimPrefix(address, "https://")
	address = strings.TrimPrefix(address, "http://")

	// Remove any path, query string, or fragment
	if idx := strings.IndexAny(address, "/?#"); idx != -1 {
		address = address[:idx]
	}

	// Add .onion suffix if missing
	if !strings.HasSuffix(address, OnionSuffix) {
		address = address + OnionSuffix
	}

	// Validate the normalized address
	if !IsValidV3Address(address) {
		if IsV2Address(address) {
			return "", ErrV2AddressDeprecated
		}
		return "", ErrInvalidOnionAddress
	}

	return address, nil
}

// Onion address validation errors.
var (
	// ErrInvalidOnionAddress is returned when an address is not a valid onion address.
	ErrInvalidOnionAddress = newOnionError("invalid onion address")

	// ErrV2AddressDeprecated is returned when a v2 address is provided.
	// V2 addresses stopped working in October 2021.
	ErrV2AddressDeprecated = newOnionError("v2 onion addresses are deprecated and no longer functional")
)

// onionError is a custom error type for onion address errors.
type onionError struct {
	message string
}

// newOnionError creates a new onion error with the given message.
func newOnionError(message string) *onionError {
	return &onionError{message: message}
}

// Error implements the error interface.
func (e *onionError) Error() string {
	return e.message
}

// ComputeV3AddressFromPublicKey computes the v3 onion address from an ed25519 public key.
// This is useful for verifying that a discovered public key matches a known address.
//
// The public key must be exactly 32 bytes (ed25519 public key size).
func ComputeV3AddressFromPublicKey(pubkey []byte) (string, error) {
	if len(pubkey) != 32 {
		return "", ErrInvalidOnionAddress
	}

	// Compute checksum
	checksum := computeV3Checksum(pubkey, OnionV3Version)

	// Construct address data: pubkey (32) + checksum (2) + version (1)
	addressData := make([]byte, 35)
	copy(addressData[:32], pubkey)
	copy(addressData[32:34], checksum)
	addressData[34] = OnionV3Version

	// Encode as base32 and add suffix
	encoded := base32.StdEncoding.EncodeToString(addressData)
	return strings.ToLower(encoded) + OnionSuffix, nil
}
