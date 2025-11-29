package deanon

import (
	"context"
	"regexp"

	"github.com/nao1215/onionscan/internal/model"
)

// CryptoAnalyzer detects cryptocurrency addresses in page content.
// Cryptocurrency addresses are correlation vectors because blockchain
// analysis can potentially link addresses to identities.
//
// Design decision: We detect multiple cryptocurrency types because:
//  1. Different services accept different cryptocurrencies
//  2. Each cryptocurrency has different privacy properties
//  3. Cross-cryptocurrency analysis is possible through exchanges
type CryptoAnalyzer struct {
	// patterns maps cryptocurrency type to detection regex.
	patterns map[string]*regexp.Regexp
}

// NewCryptoAnalyzer creates a new CryptoAnalyzer.
func NewCryptoAnalyzer() *CryptoAnalyzer {
	return &CryptoAnalyzer{
		patterns: map[string]*regexp.Regexp{
			// Bitcoin addresses (Legacy P2PKH, P2SH, Bech32)
			// Legacy: 1... or 3... (25-34 chars)
			// Bech32: bc1... (42 or 62 chars)
			"bitcoin_legacy": regexp.MustCompile(`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`),
			"bitcoin_bech32": regexp.MustCompile(`\bbc1[a-z0-9]{39,59}\b`),

			// Ethereum addresses (0x followed by 40 hex chars)
			"ethereum": regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`),

			// Monero addresses (95 chars starting with 4)
			// Subaddresses start with 8
			"monero": regexp.MustCompile(`\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b`),

			// Litecoin (L, M, or 3 prefix for legacy, ltc1 for bech32)
			"litecoin_legacy": regexp.MustCompile(`\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b`),
			"litecoin_bech32": regexp.MustCompile(`\bltc1[a-z0-9]{39,59}\b`),

			// Bitcoin Cash (bitcoincash: prefix or legacy 1/3)
			"bitcoin_cash": regexp.MustCompile(`\bbitcoincash:[qp][a-z0-9]{41}\b`),

			// Dash (X prefix)
			"dash": regexp.MustCompile(`\bX[1-9A-HJ-NP-Za-km-z]{33}\b`),

			// Zcash (t-addresses are transparent, z-addresses are shielded)
			"zcash_transparent": regexp.MustCompile(`\bt1[a-zA-Z0-9]{33}\b`),
			"zcash_shielded":    regexp.MustCompile(`\bzs[a-z0-9]{76}\b`),

			// Dogecoin (D prefix)
			"dogecoin": regexp.MustCompile(`\bD[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}\b`),
		},
	}
}

// Name returns the analyzer name.
func (a *CryptoAnalyzer) Name() string {
	return "cryptocurrency"
}

// Category returns the analyzer category.
func (a *CryptoAnalyzer) Category() string {
	return CategoryCorrelation
}

// Analyze searches for cryptocurrency addresses in all pages.
func (a *CryptoAnalyzer) Analyze(ctx context.Context, data *AnalysisData) ([]model.Finding, error) {
	findings := make([]model.Finding, 0)
	seenAddresses := make(map[string]bool)

	for _, page := range data.Pages {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		content := page.Snapshot

		for cryptoType, pattern := range a.patterns {
			matches := pattern.FindAllString(content, -1)

			for _, address := range matches {
				if seenAddresses[address] {
					continue
				}
				seenAddresses[address] = true

				severity := a.getSeverity(cryptoType)
				finding := model.Finding{
					Type:         "crypto_" + cryptoType,
					Title:        a.getTitle(cryptoType),
					Description:  a.getDescription(cryptoType),
					Severity:     severity,
					SeverityText: severity.String(),
					Value:        address,
					Location:     page.URL,
				}
				findings = append(findings, finding)

				// Add to report based on crypto type
				if data.Report != nil {
					cryptoName := a.getCryptoName(cryptoType)
					addr := model.CryptoAddress{Address: address, Type: cryptoType}
					switch cryptoName {
					case "Bitcoin":
						data.Report.AnonymityReport.AddBitcoinAddress(addr)
					case "Ethereum":
						data.Report.AnonymityReport.AddEthereumAddress(addr)
					case "Monero":
						data.Report.AnonymityReport.AddMoneroAddress(addr)
					}
				}
			}
		}
	}

	return findings, nil
}

// getTitle returns a human-readable title for the cryptocurrency type.
func (a *CryptoAnalyzer) getTitle(cryptoType string) string {
	titles := map[string]string{
		"bitcoin_legacy":    "Bitcoin Address Found",
		"bitcoin_bech32":    "Bitcoin Bech32 Address Found",
		"ethereum":          "Ethereum Address Found",
		"monero":            "Monero Address Found",
		"litecoin_legacy":   "Litecoin Address Found",
		"litecoin_bech32":   "Litecoin Bech32 Address Found",
		"bitcoin_cash":      "Bitcoin Cash Address Found",
		"dash":              "Dash Address Found",
		"zcash_transparent": "Zcash Transparent Address Found",
		"zcash_shielded":    "Zcash Shielded Address Found",
		"dogecoin":          "Dogecoin Address Found",
	}

	if title, ok := titles[cryptoType]; ok {
		return title
	}
	return "Cryptocurrency Address Found"
}

// getCryptoName returns the cryptocurrency name.
func (a *CryptoAnalyzer) getCryptoName(cryptoType string) string {
	names := map[string]string{
		"bitcoin_legacy":    "Bitcoin",
		"bitcoin_bech32":    "Bitcoin",
		"ethereum":          "Ethereum",
		"monero":            "Monero",
		"litecoin_legacy":   "Litecoin",
		"litecoin_bech32":   "Litecoin",
		"bitcoin_cash":      "Bitcoin Cash",
		"dash":              "Dash",
		"zcash_transparent": "Zcash",
		"zcash_shielded":    "Zcash",
		"dogecoin":          "Dogecoin",
	}

	if name, ok := names[cryptoType]; ok {
		return name
	}
	return "Unknown"
}

// getDescription returns a description for the cryptocurrency type.
func (a *CryptoAnalyzer) getDescription(cryptoType string) string {
	switch cryptoType {
	case "bitcoin_legacy", "bitcoin_bech32":
		return "A Bitcoin address was found. Bitcoin transactions are publicly traceable " +
			"and blockchain analysis can potentially link addresses to identities."
	case "ethereum":
		return "An Ethereum address was found. Ethereum transactions are publicly traceable " +
			"and can be analyzed to identify patterns and connections."
	case "monero":
		return "A Monero address was found. While Monero provides better privacy than Bitcoin, " +
			"the presence of an address is still noted for correlation purposes."
	case "zcash_shielded":
		return "A Zcash shielded address was found. Shielded addresses provide strong privacy, " +
			"but the address format itself is still noted."
	case "zcash_transparent":
		return "A Zcash transparent address was found. Transparent addresses do not use Zcash's " +
			"privacy features and transactions are publicly visible like Bitcoin."
	default:
		return "A cryptocurrency address was found. Blockchain analysis may be able to correlate " +
			"this address with real-world identities."
	}
}

// getSeverity returns the severity for the cryptocurrency type.
//
// Design decision: Severity varies by cryptocurrency privacy level:
//   - Transparent blockchains (Bitcoin, Ethereum): Medium (traceable)
//   - Privacy coins (Monero, Zcash shielded): Low (presence only)
func (a *CryptoAnalyzer) getSeverity(cryptoType string) model.Severity {
	switch cryptoType {
	case "monero", "zcash_shielded":
		// Privacy coins - the address itself doesn't reveal much
		return model.SeverityLow
	default:
		// Transparent blockchains - can be traced
		return model.SeverityMedium
	}
}
