// Package model defines the core data structures used throughout OnionScan.
//
// This package contains the following main types:
//   - Page: Represents a crawled web page with parsed content
//   - OnionScanReport: The main scan result structure
//   - AnonymityReport: Detailed findings about anonymity risks
//   - SimpleReport: A summarized, human-readable report
//
// Design decision: We separate models into their own package to avoid circular
// dependencies. Multiple packages (crawler, deanon, report) need to use these
// types, so centralizing them prevents import cycles.
//
// The models are designed to be serializable to JSON for report output and
// database storage.
package model
