// Package protocol provides protocol-specific scanners for detecting and analyzing
// network services on onion services.
//
// # Architecture
//
// This package implements the Scanner interface for each supported protocol,
// allowing the pipeline to execute protocol detection and analysis in a uniform way.
//
// Design decision: Each protocol scanner is implemented as a separate type rather
// than using a single generic scanner because:
//  1. Protocol-specific logic varies significantly between protocols
//  2. Type safety - each scanner can have protocol-specific methods
//  3. Easier testing - each protocol can be tested in isolation
//  4. Clearer error handling - protocol-specific errors are more descriptive
//
// # Supported Protocols
//
// The following protocols are currently supported:
//   - HTTP/HTTPS (port 80/443): Web server detection and analysis
//   - SSH (port 22): SSH server fingerprinting
//   - FTP (port 21): FTP server detection
//   - SMTP (port 25): Mail server detection
//   - IMAP (port 143/993): IMAP server detection
//   - IRC (port 6667): IRC server detection
//   - XMPP (port 5222): XMPP/Jabber server detection
//   - VNC (port 5900): VNC server detection
//   - Bitcoin (port 8333): Bitcoin node detection
//   - MongoDB (port 27017): MongoDB server detection
//   - Redis (port 6379): Redis server detection
//   - PostgreSQL (port 5432): PostgreSQL server detection
//   - MySQL (port 3306): MySQL server detection
//
// # Usage
//
// Each scanner implements the Scanner interface:
//
//	scanner := protocol.NewHTTPScanner(client)
//	result, err := scanner.Scan(ctx, "http://example.onion")
//
// # Security Considerations
//
// All protocol scanners are designed for security auditing purposes:
//   - Only connect through Tor SOCKS5 proxy
//   - Timeout protection prevents indefinite hangs
//   - No exploitation or attack capabilities
//   - Read-only operations (no write/modify)
package protocol
