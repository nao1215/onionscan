// Package deanon provides deanonymization checks for onion services.
//
// # Purpose
//
// This package analyzes crawled content and protocol scan results to identify
// potential anonymity risks that could lead to operator identification.
//
// # Design Philosophy
//
// The deanon package follows a modular analyzer pattern where each type of
// check is implemented as a separate Analyzer. This design was chosen because:
//  1. Each check type has unique logic and data requirements
//  2. Enables selective scanning based on configuration
//  3. Makes it easy to add new checks without modifying existing code
//  4. Simplifies testing of individual analysis components
//
// # Analyzer Categories
//
// Analyzers are grouped into categories based on what they detect:
//
// ## Identity Leaks
//   - Email addresses in content, headers, and certificates
//   - Social media profiles and handles
//   - Real names in metadata
//   - Organization information
//
// ## Technical Fingerprints
//   - Server software versions
//   - Framework signatures
//   - Custom headers
//   - Error page patterns
//
// ## Correlation Risks
//   - Analytics IDs (Google Analytics, etc.)
//   - Cryptocurrency addresses
//   - External resource loading
//   - Clearnet domain references
//
// ## Metadata Leaks
//   - EXIF data in images
//   - PDF metadata
//   - Office document properties
//   - Code comments and debug info
//
// # Usage
//
//	analyzer := deanon.NewAnalyzer()
//	findings := analyzer.Analyze(ctx, pages, scanResults)
//
// # Severity Levels
//
// Findings are assigned severity levels based on deanonymization risk:
//   - Critical: Direct identity revelation (real names, emails in certs)
//   - High: Strong correlation possibilities (analytics IDs, clearnet links)
//   - Medium: Useful fingerprinting info (server versions, frameworks)
//   - Low: Minor information leaks (generic headers)
//   - Info: Best practice recommendations
package deanon
