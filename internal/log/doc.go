// Package log provides secure logging functionality with automatic sanitization
// of sensitive information, built on top of the standard slog package.
//
// This package extends slog to provide:
//   - Automatic sanitization of sensitive values (cookies, tokens, secrets)
//   - Configurable log levels with verbose mode support
//   - Consistent log formatting across the application
//   - Compatibility with tornago's slog-based logging
//
// # Security Features
//
// The SecureHandler automatically sanitizes sensitive information in log output:
//   - HTTP headers (Authorization, Cookie, Set-Cookie, X-Api-Key)
//   - Secret values detected by pattern matching (passwords, tokens, keys)
//   - Cryptocurrency private keys and wallet seeds
//   - Session identifiers and authentication tokens
//
// Even in verbose mode, sensitive values are masked to prevent accidental
// exposure of secrets in logs that may be shared or stored.
//
// # Usage
//
//	// Create a secure logger
//	logger := log.NewSecureLogger(os.Stderr, true) // verbose=true
//
//	// Use as a standard slog.Logger
//	logger.Info("request sent",
//	    "cookie", "session=abc123",  // Will be sanitized to "session=***"
//	    "url", "http://example.onion",
//	)
//
//	// Set as default logger
//	slog.SetDefault(logger)
//
// # Integration with tornago
//
// The SecureHandler is compatible with tornago's slog integration:
//
//	secureLogger := log.NewSecureLogger(os.Stderr, verbose)
//	// Use with tornago components that accept *slog.Logger
package log
