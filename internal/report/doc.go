// Package report provides report generation and output functionality.
//
// This package contains writers for different output formats:
//   - SimpleWriter: Human-readable text output for terminal display
//   - JSONWriter: Structured JSON output for tool integration
//
// Design decision: We separate report writing from report data structures
// (which are in the model package) to follow the single responsibility
// principle. This allows adding new output formats without modifying
// the core data structures.
//
// Writers implement the Writer interface, allowing them to be used
// interchangeably and composed for multi-format output.
package report
