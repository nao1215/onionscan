package log

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// TestSecureHandler_SanitizesSensitiveKeys tests that sensitive keys are sanitized.
func TestSecureHandler_SanitizesSensitiveKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		key      string
		value    string
		wantMask bool
	}{
		{
			name:     "cookie key is sanitized",
			key:      "cookie",
			value:    "session=abc123",
			wantMask: true,
		},
		{
			name:     "Cookie key (uppercase) is sanitized",
			key:      "Cookie",
			value:    "session=abc123",
			wantMask: true,
		},
		{
			name:     "authorization key is sanitized",
			key:      "authorization",
			value:    "Bearer token123",
			wantMask: true,
		},
		{
			name:     "password key is sanitized",
			key:      "password",
			value:    "secretpassword",
			wantMask: true,
		},
		{
			name:     "token key is sanitized",
			key:      "token",
			value:    "jwt.token.here",
			wantMask: true,
		},
		{
			name:     "api_key key is sanitized",
			key:      "api_key",
			value:    "sk_live_123456789",
			wantMask: true,
		},
		{
			name:     "secret_key key is sanitized",
			key:      "secret_key",
			value:    "my-secret-key-value",
			wantMask: true,
		},
		{
			name:     "session_id key is sanitized",
			key:      "session_id",
			value:    "sess_12345",
			wantMask: true,
		},
		{
			name:     "private_key key is sanitized",
			key:      "private_key",
			value:    "-----BEGIN PRIVATE KEY-----",
			wantMask: true,
		},
		{
			name:     "x-api-key header is sanitized",
			key:      "x-api-key",
			value:    "apikey123",
			wantMask: true,
		},
		{
			name:     "url key is NOT sanitized",
			key:      "url",
			value:    "http://example.onion",
			wantMask: false,
		},
		{
			name:     "target key is NOT sanitized",
			key:      "target",
			value:    "example.onion",
			wantMask: false,
		},
		{
			name:     "port key is NOT sanitized",
			key:      "port",
			value:    "8080",
			wantMask: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			logger := NewSecureLogger(&buf, true)

			logger.Info("test message", tt.key, tt.value)

			output := buf.String()

			if tt.wantMask {
				if strings.Contains(output, tt.value) {
					t.Errorf("expected value %q to be masked, but found in output: %s", tt.value, output)
				}
				if !strings.Contains(output, MaskValue) {
					t.Errorf("expected mask value %q in output, but not found: %s", MaskValue, output)
				}
			} else {
				if !strings.Contains(output, tt.value) {
					t.Errorf("expected value %q to be present in output, but not found: %s", tt.value, output)
				}
			}
		})
	}
}

// TestSecureHandler_SanitizesSensitivePatterns tests that values matching sensitive patterns are sanitized.
func TestSecureHandler_SanitizesSensitivePatterns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		key      string
		value    string
		wantMask bool
	}{
		{
			name:     "JWT token is sanitized regardless of key",
			key:      "data",
			value:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			wantMask: true,
		},
		{
			name:     "Bearer token is sanitized regardless of key",
			key:      "header",
			value:    "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
			wantMask: true,
		},
		{
			name:     "Basic auth is sanitized regardless of key",
			key:      "auth_header",
			value:    "Basic dXNlcm5hbWU6cGFzc3dvcmQ=",
			wantMask: true,
		},
		{
			name:     "AWS access key is sanitized regardless of key",
			key:      "aws_key",
			value:    "AKIAIOSFODNN7EXAMPLE",
			wantMask: true,
		},
		{
			name:     "private key marker is sanitized",
			key:      "content",
			value:    "-----BEGIN RSA PRIVATE KEY-----",
			wantMask: true,
		},
		{
			name:     "ed25519v1 secret is sanitized",
			key:      "file_content",
			value:    "== ed25519v1-secret: type0 ==",
			wantMask: true,
		},
		{
			name:     "normal URL is NOT sanitized",
			key:      "link",
			value:    "http://example.onion/page",
			wantMask: false,
		},
		{
			name:     "short string is NOT sanitized",
			key:      "status",
			value:    "ok",
			wantMask: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			logger := NewSecureLogger(&buf, true)

			logger.Info("test message", tt.key, tt.value)

			output := buf.String()

			if tt.wantMask {
				if strings.Contains(output, tt.value) {
					t.Errorf("expected value to be masked, but found in output: %s", output)
				}
				if !strings.Contains(output, MaskValue) {
					t.Errorf("expected mask value in output, but not found: %s", output)
				}
			} else {
				if !strings.Contains(output, tt.value) {
					t.Errorf("expected value %q to be present in output, but not found: %s", tt.value, output)
				}
			}
		})
	}
}

// TestSecureHandler_LogLevels tests that log levels are respected.
func TestSecureHandler_LogLevels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		verbose    bool
		logLevel   slog.Level
		shouldShow bool
	}{
		{
			name:       "debug message shown in verbose mode",
			verbose:    true,
			logLevel:   slog.LevelDebug,
			shouldShow: true,
		},
		{
			name:       "debug message hidden in non-verbose mode",
			verbose:    false,
			logLevel:   slog.LevelDebug,
			shouldShow: false,
		},
		{
			name:       "info message shown in verbose mode",
			verbose:    true,
			logLevel:   slog.LevelInfo,
			shouldShow: true,
		},
		{
			name:       "info message hidden in non-verbose mode",
			verbose:    false,
			logLevel:   slog.LevelInfo,
			shouldShow: false,
		},
		{
			name:       "warn message shown in verbose mode",
			verbose:    true,
			logLevel:   slog.LevelWarn,
			shouldShow: true,
		},
		{
			name:       "warn message shown in non-verbose mode",
			verbose:    false,
			logLevel:   slog.LevelWarn,
			shouldShow: true,
		},
		{
			name:       "error message shown in verbose mode",
			verbose:    true,
			logLevel:   slog.LevelError,
			shouldShow: true,
		},
		{
			name:       "error message shown in non-verbose mode",
			verbose:    false,
			logLevel:   slog.LevelError,
			shouldShow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			logger := NewSecureLogger(&buf, tt.verbose)

			testMsg := "test_unique_message_12345"

			switch tt.logLevel {
			case slog.LevelDebug:
				logger.Debug(testMsg)
			case slog.LevelInfo:
				logger.Info(testMsg)
			case slog.LevelWarn:
				logger.Warn(testMsg)
			case slog.LevelError:
				logger.Error(testMsg)
			}

			output := buf.String()
			hasMessage := strings.Contains(output, testMsg)

			if tt.shouldShow && !hasMessage {
				t.Errorf("expected message to be shown, but not found in output: %s", output)
			}
			if !tt.shouldShow && hasMessage {
				t.Errorf("expected message to be hidden, but found in output: %s", output)
			}
		})
	}
}

// TestSecureHandler_WithAttrs tests that WithAttrs sanitizes attributes.
func TestSecureHandler_WithAttrs(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := NewSecureLogger(&buf, true)

	// Add sensitive attribute via WithAttrs
	childLogger := logger.With("password", "secret123")
	childLogger.Info("test message")

	output := buf.String()

	if strings.Contains(output, "secret123") {
		t.Errorf("expected password to be masked in WithAttrs, but found in output: %s", output)
	}
	if !strings.Contains(output, MaskValue) {
		t.Errorf("expected mask value in output, but not found: %s", output)
	}
}

// TestSecureHandler_WithGroup tests that WithGroup works correctly.
func TestSecureHandler_WithGroup(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := NewSecureLogger(&buf, true)

	// Add group
	groupLogger := logger.WithGroup("request")
	groupLogger.Info("test message", "url", "http://example.onion", "cookie", "session=abc")

	output := buf.String()

	// URL should be visible
	if !strings.Contains(output, "http://example.onion") {
		t.Errorf("expected url to be visible, but not found in output: %s", output)
	}

	// Cookie should be masked
	if strings.Contains(output, "session=abc") {
		t.Errorf("expected cookie to be masked, but found in output: %s", output)
	}
}

// TestNewSecureJSONLogger tests JSON logger creation.
func TestNewSecureJSONLogger(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := NewSecureJSONLogger(&buf, true)

	logger.Info("test message", "password", "secret")

	output := buf.String()

	// Should be JSON format
	if !strings.Contains(output, "{") || !strings.Contains(output, "}") {
		t.Errorf("expected JSON format, but got: %s", output)
	}

	// Password should be masked
	if strings.Contains(output, "secret") {
		t.Errorf("expected password to be masked, but found in output: %s", output)
	}
}

// TestContainsSensitiveKeyword tests the containsSensitiveKeyword helper.
func TestContainsSensitiveKeyword(t *testing.T) {
	t.Parallel()

	tests := []struct {
		key      string
		expected bool
	}{
		// Sensitive keywords - should be masked
		{"user_password", true},
		{"api_token", true},
		{"secret_value", true},
		{"auth_header", true},
		{"private_data", true},
		{"credential_file", true},
		{"seed_phrase", true},
		{"mnemonic_words", true},

		// Normal keys - should NOT be masked
		{"url", false},
		{"host", false},
		{"port", false},
		{"target", false},

		// False positive prevention: "key" alone is too broad
		// These should NOT be masked as they are not sensitive
		{"primary_key", false},   // database terminology
		{"foreign_key", false},   // database terminology
		{"keyboard", false},      // UI terminology
		{"hotkey", false},        // UI terminology
		{"monkey", false},        // general word
		{"turkey", false},        // general word
		{"donkey", false},        // general word
		{"key_name", false},      // generic key identifier
		{"cache_key", false},     // caching terminology
		{"lookup_key", false},    // data structure terminology
		{"sort_key", false},      // sorting terminology
		{"partition_key", false}, // database/distributed systems
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			t.Parallel()

			result := containsSensitiveKeyword(tt.key)
			if result != tt.expected {
				t.Errorf("containsSensitiveKeyword(%q) = %v, want %v", tt.key, result, tt.expected)
			}
		})
	}
}

// TestNewSecureHandler_NilHandler tests that nil handler is handled gracefully.
func TestNewSecureHandler_NilHandler(t *testing.T) {
	t.Parallel()

	// Should not panic with nil handler
	handler := NewSecureHandler(nil)
	if handler == nil {
		t.Error("expected non-nil handler")
	}

	// Should be able to use the handler
	logger := slog.New(handler)
	logger.Info("test message") // Should not panic
}

// TestIsSensitiveValue tests the isSensitiveValue helper.
func TestIsSensitiveValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{
			name:     "JWT token",
			value:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expected: true,
		},
		{
			name:     "Bearer token",
			value:    "Bearer abc123xyz",
			expected: true,
		},
		{
			name:     "Basic auth",
			value:    "Basic dXNlcjpwYXNz",
			expected: true,
		},
		{
			name:     "AWS access key",
			value:    "AKIAIOSFODNN7EXAMPLE",
			expected: true,
		},
		{
			name:     "Private key header",
			value:    "-----BEGIN RSA PRIVATE KEY-----",
			expected: true,
		},
		{
			name:     "ed25519v1 secret",
			value:    "== ed25519v1-secret: type0 ==",
			expected: true,
		},
		{
			name:     "normal string",
			value:    "hello world",
			expected: false,
		},
		{
			name:     "URL",
			value:    "http://example.onion/page",
			expected: false,
		},
		{
			name:     "short alphanumeric",
			value:    "abc123",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := isSensitiveValue(tt.value)
			if result != tt.expected {
				t.Errorf("isSensitiveValue(%q) = %v, want %v", tt.value, result, tt.expected)
			}
		})
	}
}
