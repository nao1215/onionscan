// Package tor provides Tor network connectivity for OnionScan.
//
// This package wraps the tornago library to provide SOCKS5 proxy connections
// through the Tor network. It handles connection management, proxy status
// verification, and provides HTTP clients configured for Tor.
//
// Design decision: We use tornago instead of directly implementing SOCKS5
// because tornago provides a well-tested, maintained implementation with
// additional features like automatic retry and connection pooling. This reduces
// our maintenance burden and leverages existing expertise in Tor connectivity.
//
// The package is designed to be used with dependency injection - create a
// Client and pass it to components that need Tor connectivity rather than
// using global state.
package tor
