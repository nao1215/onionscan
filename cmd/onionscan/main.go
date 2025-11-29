// Package main provides the entry point for the OnionScan CLI.
//
// OnionScan is a security auditing tool for Tor hidden services (.onion addresses).
// It identifies OPSEC issues, configuration errors, and anonymity risks.
//
// Usage:
//
//	onionscan scan <onion-address>
//	onionscan scan --list <file>
//
// See --help for all available options.
package main

// main is the entry point for OnionScan.
func main() {
	Execute()
}
