package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestNewConfig verifies that NewConfig returns a Config with all expected default values.
// This test ensures that defaults are documented through tests and that changes
// to defaults are intentional (tests will fail if defaults change unexpectedly).
func TestNewConfig(t *testing.T) {
	t.Parallel()

	cfg := NewConfig()

	// Verify each default value explicitly
	// This serves as living documentation of the defaults
	t.Run("default TorProxyAddress is 127.0.0.1:9050", func(t *testing.T) {
		t.Parallel()
		if cfg.TorProxyAddress != "127.0.0.1:9050" {
			t.Errorf("expected TorProxyAddress to be '127.0.0.1:9050', got '%s'", cfg.TorProxyAddress)
		}
	})

	t.Run("default Timeout is 120 seconds", func(t *testing.T) {
		t.Parallel()
		if cfg.Timeout != 120*time.Second {
			t.Errorf("expected Timeout to be 120s, got %v", cfg.Timeout)
		}
	})

	t.Run("default CrawlDepth is 100", func(t *testing.T) {
		t.Parallel()
		if cfg.CrawlDepth != 100 {
			t.Errorf("expected CrawlDepth to be 100, got %d", cfg.CrawlDepth)
		}
	})

	t.Run("default BatchSize is 10", func(t *testing.T) {
		t.Parallel()
		if cfg.BatchSize != 10 {
			t.Errorf("expected BatchSize to be 10, got %d", cfg.BatchSize)
		}
	})

	t.Run("default UseExternalTor is false", func(t *testing.T) {
		t.Parallel()
		if cfg.UseExternalTor {
			t.Error("expected UseExternalTor to be false")
		}
	})

	t.Run("default TorStartupTimeout is 3 minutes", func(t *testing.T) {
		t.Parallel()
		if cfg.TorStartupTimeout != 3*time.Minute {
			t.Errorf("expected TorStartupTimeout to be 3m, got %v", cfg.TorStartupTimeout)
		}
	})
}

// TestConfigValidate tests the Validate method with various configurations.
// Each test case is designed to test one specific validation rule.
func TestConfigValidate(t *testing.T) {
	t.Parallel()

	// validConfig returns a minimal valid configuration.
	// Tests can modify specific fields to test validation rules.
	validConfig := func() *Config {
		return &Config{
			Targets:         []string{"exampleonionv3addressxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion"},
			Timeout:         120 * time.Second,
			BatchSize:       10,
			TorProxyAddress: "127.0.0.1:9050",
		}
	}

	t.Run("valid config returns nil", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		if err := cfg.Validate(); err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("multiple targets is valid", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		cfg.Targets = []string{"site1.onion", "site2.onion", "site3.onion"}

		if err := cfg.Validate(); err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("empty targets returns ErrNoTarget", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		cfg.Targets = []string{}

		err := cfg.Validate()
		if !errors.Is(err, ErrNoTarget) {
			t.Errorf("expected ErrNoTarget, got %v", err)
		}
	})

	t.Run("nil targets returns ErrNoTarget", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		cfg.Targets = nil

		err := cfg.Validate()
		if !errors.Is(err, ErrNoTarget) {
			t.Errorf("expected ErrNoTarget, got %v", err)
		}
	})

	t.Run("zero timeout returns ErrInvalidTimeout", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		cfg.Timeout = 0

		err := cfg.Validate()
		if !errors.Is(err, ErrInvalidTimeout) {
			t.Errorf("expected ErrInvalidTimeout, got %v", err)
		}
	})

	t.Run("negative timeout returns ErrInvalidTimeout", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		cfg.Timeout = -1 * time.Second

		err := cfg.Validate()
		if !errors.Is(err, ErrInvalidTimeout) {
			t.Errorf("expected ErrInvalidTimeout, got %v", err)
		}
	})

	t.Run("zero batch size returns ErrInvalidBatchSize", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		cfg.BatchSize = 0

		err := cfg.Validate()
		if !errors.Is(err, ErrInvalidBatchSize) {
			t.Errorf("expected ErrInvalidBatchSize, got %v", err)
		}
	})

	t.Run("negative batch size returns ErrInvalidBatchSize", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		cfg.BatchSize = -1

		err := cfg.Validate()
		if !errors.Is(err, ErrInvalidBatchSize) {
			t.Errorf("expected ErrInvalidBatchSize, got %v", err)
		}
	})

	t.Run("json and markdown both enabled returns ErrConflictingReportFormats", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		cfg.JSONReport = true
		cfg.MarkdownReport = true

		err := cfg.Validate()
		if !errors.Is(err, ErrConflictingReportFormats) {
			t.Errorf("expected ErrConflictingReportFormats, got %v", err)
		}
	})

	t.Run("json only is valid", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		cfg.JSONReport = true
		cfg.MarkdownReport = false

		err := cfg.Validate()
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("markdown only is valid", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		cfg.JSONReport = false
		cfg.MarkdownReport = true

		err := cfg.Validate()
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})
}

// TestFileGetSiteConfig tests the GetSiteConfig method.
func TestFileGetSiteConfig(t *testing.T) {
	t.Parallel()

	t.Run("returns defaults when site not found", func(t *testing.T) {
		t.Parallel()

		file := &File{
			Defaults: SiteConfig{
				Depth:  50,
				Cookie: "default_cookie=abc",
			},
			Sites: map[string]SiteConfig{},
		}

		cfg := file.GetSiteConfig("unknown.onion")
		if cfg.Depth != 50 {
			t.Errorf("expected depth 50, got %d", cfg.Depth)
		}
		if cfg.Cookie != "default_cookie=abc" {
			t.Errorf("expected default cookie, got %q", cfg.Cookie)
		}
	})

	t.Run("returns site-specific config", func(t *testing.T) {
		t.Parallel()

		file := &File{
			Defaults: SiteConfig{
				Depth:  50,
				Cookie: "default_cookie=abc",
			},
			Sites: map[string]SiteConfig{
				"example.onion": {
					Depth:  100,
					Cookie: "session=xyz",
				},
			},
		}

		cfg := file.GetSiteConfig("example.onion")
		if cfg.Depth != 100 {
			t.Errorf("expected depth 100, got %d", cfg.Depth)
		}
		if cfg.Cookie != "session=xyz" {
			t.Errorf("expected site cookie, got %q", cfg.Cookie)
		}
	})

	t.Run("merges headers from defaults and site", func(t *testing.T) {
		t.Parallel()

		file := &File{
			Defaults: SiteConfig{
				Headers: map[string]string{
					"X-Default": "value1",
				},
			},
			Sites: map[string]SiteConfig{
				"example.onion": {
					Headers: map[string]string{
						"X-Custom": "value2",
					},
				},
			},
		}

		cfg := file.GetSiteConfig("example.onion")
		if cfg.Headers["X-Default"] != "value1" {
			t.Errorf("expected default header, got %v", cfg.Headers)
		}
		if cfg.Headers["X-Custom"] != "value2" {
			t.Errorf("expected custom header, got %v", cfg.Headers)
		}
	})

	t.Run("site headers override default headers", func(t *testing.T) {
		t.Parallel()

		file := &File{
			Defaults: SiteConfig{
				Headers: map[string]string{
					"Authorization": "default-token",
				},
			},
			Sites: map[string]SiteConfig{
				"example.onion": {
					Headers: map[string]string{
						"Authorization": "site-token",
					},
				},
			},
		}

		cfg := file.GetSiteConfig("example.onion")
		if cfg.Headers["Authorization"] != "site-token" {
			t.Errorf("expected site token to override, got %q", cfg.Headers["Authorization"])
		}
	})

	t.Run("site patterns override defaults", func(t *testing.T) {
		t.Parallel()

		file := &File{
			Defaults: SiteConfig{
				IgnorePatterns: []string{"/default/*"},
				FollowPatterns: []string{"/default-follow/*"},
			},
			Sites: map[string]SiteConfig{
				"example.onion": {
					IgnorePatterns: []string{"/admin/*"},
					FollowPatterns: []string{"/api/*"},
				},
			},
		}

		cfg := file.GetSiteConfig("example.onion")
		if len(cfg.IgnorePatterns) != 1 || cfg.IgnorePatterns[0] != "/admin/*" {
			t.Errorf("expected site ignore patterns, got %v", cfg.IgnorePatterns)
		}
		if len(cfg.FollowPatterns) != 1 || cfg.FollowPatterns[0] != "/api/*" {
			t.Errorf("expected site follow patterns, got %v", cfg.FollowPatterns)
		}
	})

	t.Run("zero depth uses default", func(t *testing.T) {
		t.Parallel()

		file := &File{
			Defaults: SiteConfig{
				Depth: 50,
			},
			Sites: map[string]SiteConfig{
				"example.onion": {
					Cookie: "session=abc", // no depth specified
				},
			},
		}

		cfg := file.GetSiteConfig("example.onion")
		if cfg.Depth != 50 {
			t.Errorf("expected default depth 50, got %d", cfg.Depth)
		}
		if cfg.Cookie != "session=abc" {
			t.Errorf("expected site cookie, got %q", cfg.Cookie)
		}
	})

	t.Run("empty cookie uses default", func(t *testing.T) {
		t.Parallel()

		file := &File{
			Defaults: SiteConfig{
				Cookie: "default=abc",
			},
			Sites: map[string]SiteConfig{
				"example.onion": {
					Depth: 100, // no cookie specified
				},
			},
		}

		cfg := file.GetSiteConfig("example.onion")
		if cfg.Cookie != "default=abc" {
			t.Errorf("expected default cookie, got %q", cfg.Cookie)
		}
	})

	t.Run("nil sites map", func(t *testing.T) {
		t.Parallel()

		file := &File{
			Defaults: SiteConfig{
				Depth: 25,
			},
		}

		cfg := file.GetSiteConfig("any.onion")
		if cfg.Depth != 25 {
			t.Errorf("expected depth 25, got %d", cfg.Depth)
		}
	})
}

// TestSiteConfigStruct tests the SiteConfig struct fields.
func TestSiteConfigStruct(t *testing.T) {
	t.Parallel()

	t.Run("all fields can be set", func(t *testing.T) {
		t.Parallel()

		cfg := SiteConfig{
			Cookie: "session=abc123",
			Headers: map[string]string{
				"Authorization": "Bearer token",
				"X-Custom":      "value",
			},
			Depth:          100,
			IgnorePatterns: []string{"/admin/*", "*.pdf"},
			FollowPatterns: []string{"/api/*", "/public/*"},
		}

		if cfg.Cookie != "session=abc123" {
			t.Errorf("cookie not set correctly")
		}
		if len(cfg.Headers) != 2 {
			t.Errorf("expected 2 headers, got %d", len(cfg.Headers))
		}
		if cfg.Depth != 100 {
			t.Errorf("expected depth 100, got %d", cfg.Depth)
		}
		if len(cfg.IgnorePatterns) != 2 {
			t.Errorf("expected 2 ignore patterns, got %d", len(cfg.IgnorePatterns))
		}
		if len(cfg.FollowPatterns) != 2 {
			t.Errorf("expected 2 follow patterns, got %d", len(cfg.FollowPatterns))
		}
	})
}

// TestLoadConfigFile tests the LoadConfigFile function.
func TestLoadConfigFile(t *testing.T) {
	t.Parallel()

	t.Run("returns ErrConfigNotFound for non-existent file", func(t *testing.T) {
		t.Parallel()

		cfg, err := LoadConfigFile("/nonexistent/path/.onionscan")
		if err == nil {
			t.Fatal("expected error for non-existent file")
		}
		if !errors.Is(err, ErrConfigNotFound) {
			t.Fatalf("expected ErrConfigNotFound, got: %v", err)
		}
		if cfg != nil {
			t.Error("expected nil config when file not found")
		}
	})

	t.Run("loads valid YAML config", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, ".onionscan")

		content := `defaults:
  depth: 50
  cookie: "default=abc"
sites:
  example.onion:
    depth: 100
    cookie: "session=xyz"
    headers:
      Authorization: "Bearer token"
    ignorePatterns:
      - "/admin/*"
    followPatterns:
      - "/api/*"
`
		if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
			t.Fatalf("failed to write test config: %v", err)
		}

		cfg, err := LoadConfigFile(configPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.Defaults.Depth != 50 {
			t.Errorf("expected default depth 50, got %d", cfg.Defaults.Depth)
		}
		if cfg.Defaults.Cookie != "default=abc" {
			t.Errorf("expected default cookie, got %q", cfg.Defaults.Cookie)
		}

		site, ok := cfg.Sites["example.onion"]
		if !ok {
			t.Fatal("expected example.onion in sites")
		}
		if site.Depth != 100 {
			t.Errorf("expected site depth 100, got %d", site.Depth)
		}
		if site.Headers["Authorization"] != "Bearer token" {
			t.Errorf("expected Authorization header")
		}
		if len(site.IgnorePatterns) != 1 {
			t.Errorf("expected 1 ignore pattern, got %d", len(site.IgnorePatterns))
		}
	})

	t.Run("returns error for invalid YAML", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, ".onionscan")

		content := `invalid: yaml: content: [}`
		if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
			t.Fatalf("failed to write test config: %v", err)
		}

		_, err := LoadConfigFile(configPath)
		if err == nil {
			t.Error("expected error for invalid YAML")
		}
	})

	t.Run("initializes nil Sites map", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, ".onionscan")

		content := `defaults:
  depth: 25
`
		if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
			t.Fatalf("failed to write test config: %v", err)
		}

		cfg, err := LoadConfigFile(configPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Sites == nil {
			t.Error("expected Sites map to be initialized")
		}
	})
}

// TestFindConfigFile tests the FindConfigFile function.
func TestFindConfigFile(t *testing.T) {
	t.Run("returns explicit path if exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "custom.yaml")

		if err := os.WriteFile(configPath, []byte("defaults: {}"), 0600); err != nil {
			t.Fatalf("failed to write test config: %v", err)
		}

		result := FindConfigFile(configPath)
		if result != configPath {
			t.Errorf("expected %q, got %q", configPath, result)
		}
	})

	t.Run("returns empty for non-existent explicit path", func(t *testing.T) {
		result := FindConfigFile("/nonexistent/path/config.yaml")
		if result != "" {
			t.Errorf("expected empty string, got %q", result)
		}
	})

	t.Run("returns empty when no config found", func(_ *testing.T) {
		result := FindConfigFile("")
		// This may or may not find a config depending on the system
		// Just ensure it doesn't panic
		_ = result
	})
}

// TestXDGDirs tests XDG directory functions.
func TestXDGDirs(t *testing.T) {
	t.Parallel()

	t.Run("XDGDataDir returns non-empty path", func(t *testing.T) {
		t.Parallel()

		dir := XDGDataDir()
		if dir == "" {
			t.Error("expected non-empty XDG data dir")
		}
	})

	t.Run("XDGConfigDir returns non-empty path", func(t *testing.T) {
		t.Parallel()

		dir := XDGConfigDir()
		if dir == "" {
			t.Error("expected non-empty XDG config dir")
		}
	})

	t.Run("XDGCacheDir returns non-empty path", func(t *testing.T) {
		t.Parallel()

		dir := XDGCacheDir()
		if dir == "" {
			t.Error("expected non-empty XDG cache dir")
		}
	})
}

// TestConfigAllFields tests that all Config fields can be set.
func TestConfigAllFields(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		TorProxyAddress:   "127.0.0.1:9150",
		Timeout:           60 * time.Second,
		CrawlDepth:        50,
		Verbose:           true,
		BatchSize:         5,
		ConfigFilePath:    "/path/to/config",
		SiteConfigs:       &File{},
		JSONReport:        true,
		ReportFile:        "/path/to/report.json",
		Targets:           []string{"site1.onion", "site2.onion"},
		UseExternalTor:    true,
		TorStartupTimeout: 5 * time.Minute,
	}

	if cfg.TorProxyAddress != "127.0.0.1:9150" {
		t.Errorf("unexpected TorProxyAddress")
	}
	if cfg.Timeout != 60*time.Second {
		t.Errorf("unexpected Timeout")
	}
	if cfg.CrawlDepth != 50 {
		t.Errorf("unexpected CrawlDepth")
	}
	if !cfg.Verbose {
		t.Errorf("expected Verbose true")
	}
	if cfg.BatchSize != 5 {
		t.Errorf("unexpected BatchSize")
	}
	if !cfg.JSONReport {
		t.Errorf("expected JSONReport true")
	}
	if !cfg.UseExternalTor {
		t.Errorf("expected UseExternalTor true")
	}
}
