package log

import (
	"context"
	"io"
	"log/slog"
	"regexp"
	"strings"
)

// sensitiveKeys contains attribute keys that should always be sanitized.
// These keys commonly contain sensitive information that should not be logged.
var sensitiveKeys = map[string]bool{
	// HTTP headers
	"authorization":       true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"x-auth-token":        true,
	"proxy-authorization": true,

	// Authentication
	"password":      true,
	"passwd":        true,
	"secret":        true,
	"token":         true,
	"api_key":       true,
	"apikey":        true,
	"api-key":       true,
	"access_token":  true,
	"refresh_token": true,
	"private_key":   true,
	"privatekey":    true,
	"secret_key":    true,
	"secretkey":     true,

	// Session
	"session":    true,
	"session_id": true,
	"sessionid":  true,
	"sid":        true,
	"jsessionid": true,

	// Credentials
	"credential":  true,
	"credentials": true,
	"auth":        true,

	// Cryptocurrency
	"seed":       true,
	"mnemonic":   true,
	"wallet_key": true,
}

// sensitivePatterns contains regex patterns that indicate sensitive values.
// Values matching these patterns will be sanitized regardless of key name.
var sensitivePatterns = []*regexp.Regexp{
	// JWT tokens
	regexp.MustCompile(`^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$`),

	// Bearer tokens
	regexp.MustCompile(`(?i)^bearer\s+.+`),

	// Basic auth
	regexp.MustCompile(`(?i)^basic\s+[A-Za-z0-9+/=]+$`),

	// API keys (common formats)
	regexp.MustCompile(`^[a-zA-Z0-9]{32,}$`), // Long alphanumeric strings

	// AWS access keys
	regexp.MustCompile(`^AKIA[0-9A-Z]{16}$`),

	// Private key markers
	regexp.MustCompile(`(?i)-----BEGIN.*(PRIVATE|SECRET).*KEY-----`),

	// ed25519v1 secret (Tor v3 onion)
	regexp.MustCompile(`== ed25519v1-secret:`),
}

// MaskValue is the string used to replace sensitive values.
const MaskValue = "***REDACTED***"

// SecureHandler wraps an slog.Handler to sanitize sensitive information.
// It intercepts log records and sanitizes attribute values that match
// sensitive key names or value patterns before passing them to the
// underlying handler.
//
// Design decision: We use a handler wrapper rather than a custom logger
// because:
//  1. It integrates seamlessly with standard slog APIs
//  2. It works with any underlying handler (text, JSON, etc.)
//  3. It's compatible with tornago and other slog-based libraries
type SecureHandler struct {
	// handler is the underlying slog handler that receives sanitized records.
	handler slog.Handler
}

// NewSecureHandler creates a new SecureHandler wrapping the given handler.
// All log attributes will be sanitized before being passed to the underlying handler.
// If handler is nil, the returned SecureHandler will use slog.Default().Handler().
func NewSecureHandler(handler slog.Handler) *SecureHandler {
	if handler == nil {
		handler = slog.Default().Handler()
	}
	return &SecureHandler{handler: handler}
}

// Enabled reports whether the handler handles records at the given level.
// It delegates to the underlying handler.
func (h *SecureHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

// Handle sanitizes the record's attributes and passes it to the underlying handler.
func (h *SecureHandler) Handle(ctx context.Context, r slog.Record) error {
	// Create a new record with sanitized attributes
	sanitized := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)

	// Sanitize each attribute
	r.Attrs(func(a slog.Attr) bool {
		sanitized.AddAttrs(h.sanitizeAttr(a))
		return true
	})

	return h.handler.Handle(ctx, sanitized)
}

// WithAttrs returns a new handler with the given attributes added.
// Attributes are sanitized before being added.
func (h *SecureHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	sanitizedAttrs := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		sanitizedAttrs[i] = h.sanitizeAttr(a)
	}
	return &SecureHandler{handler: h.handler.WithAttrs(sanitizedAttrs)}
}

// WithGroup returns a new handler with the given group name.
func (h *SecureHandler) WithGroup(name string) slog.Handler {
	return &SecureHandler{handler: h.handler.WithGroup(name)}
}

// sanitizeAttr sanitizes a single attribute, recursively handling groups.
func (h *SecureHandler) sanitizeAttr(a slog.Attr) slog.Attr {
	// Handle groups recursively
	if a.Value.Kind() == slog.KindGroup {
		attrs := a.Value.Group()
		sanitizedAttrs := make([]slog.Attr, len(attrs))
		for i, groupAttr := range attrs {
			sanitizedAttrs[i] = h.sanitizeAttr(groupAttr)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(sanitizedAttrs...)}
	}

	// Check if the key indicates sensitive data
	keyLower := strings.ToLower(a.Key)
	if sensitiveKeys[keyLower] || containsSensitiveKeyword(keyLower) {
		return slog.String(a.Key, MaskValue)
	}

	// Check if the value matches sensitive patterns
	if a.Value.Kind() == slog.KindString {
		strVal := a.Value.String()
		if isSensitiveValue(strVal) {
			return slog.String(a.Key, MaskValue)
		}
	}

	return a
}

// containsSensitiveKeyword checks if the key contains sensitive keywords.
// Note: We intentionally exclude the bare "key" keyword as it causes false positives
// (e.g., "primary_key", "keyboard", "monkey"). Specific key-related patterns like
// "api_key", "private_key", "secret_key" are covered by the sensitiveKeys map.
func containsSensitiveKeyword(key string) bool {
	sensitiveKeywords := []string{
		"password", "passwd", "secret", "token", "auth",
		"credential", "private", "seed", "mnemonic",
	}

	for _, keyword := range sensitiveKeywords {
		if strings.Contains(key, keyword) {
			return true
		}
	}
	return false
}

// isSensitiveValue checks if a value matches sensitive patterns.
func isSensitiveValue(value string) bool {
	for _, pattern := range sensitivePatterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

// NewSecureLogger creates a new slog.Logger with secure handling.
// The logger sanitizes sensitive information in all log output.
//
// Parameters:
//   - w: The io.Writer to write log output to (typically os.Stderr)
//   - verbose: If true, sets log level to Debug; otherwise Warn
//
// Returns a *slog.Logger that can be used with slog.SetDefault() or passed
// to components that accept *slog.Logger (including tornago).
func NewSecureLogger(w io.Writer, verbose bool) *slog.Logger {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelDebug
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	textHandler := slog.NewTextHandler(w, opts)
	secureHandler := NewSecureHandler(textHandler)

	return slog.New(secureHandler)
}

// NewSecureJSONLogger creates a new slog.Logger with secure handling
// that outputs JSON format. Useful for structured log aggregation.
//
// Parameters:
//   - w: The io.Writer to write log output to
//   - verbose: If true, sets log level to Debug; otherwise Warn
//
// Returns a *slog.Logger configured for JSON output with sanitization.
func NewSecureJSONLogger(w io.Writer, verbose bool) *slog.Logger {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelDebug
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	jsonHandler := slog.NewJSONHandler(w, opts)
	secureHandler := NewSecureHandler(jsonHandler)

	return slog.New(secureHandler)
}
