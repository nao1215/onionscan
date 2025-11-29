package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nao1215/onionscan/internal/config"
	"github.com/nao1215/onionscan/internal/database"
	"github.com/nao1215/onionscan/internal/model"
)

// TestNewScanCmd tests the scan command creation.
func TestNewScanCmd(t *testing.T) {
	t.Parallel()

	cmd := NewScanCmd()

	t.Run("has correct use", func(t *testing.T) {
		t.Parallel()
		if cmd.Use != "scan [onion-address]" {
			t.Errorf("expected use 'scan [onion-address]', got %q", cmd.Use)
		}
	})

	t.Run("has short description", func(t *testing.T) {
		t.Parallel()
		if cmd.Short == "" {
			t.Error("expected non-empty short description")
		}
	})

	t.Run("has long description", func(t *testing.T) {
		t.Parallel()
		if cmd.Long == "" {
			t.Error("expected non-empty long description")
		}
	})

	t.Run("requires at least one argument", func(t *testing.T) {
		t.Parallel()
		if cmd.Args == nil {
			t.Error("expected Args validator")
		}
	})

	t.Run("has external-tor flag", func(t *testing.T) {
		t.Parallel()
		flag := cmd.Flags().Lookup("external-tor")
		if flag == nil {
			t.Fatal("expected external-tor flag")
		}
		if flag.Shorthand != "e" {
			t.Errorf("expected shorthand 'e', got %q", flag.Shorthand)
		}
	})

	t.Run("has tor-timeout flag", func(t *testing.T) {
		t.Parallel()
		flag := cmd.Flags().Lookup("tor-timeout")
		if flag == nil {
			t.Fatal("expected tor-timeout flag")
		}
		if flag.Shorthand != "T" {
			t.Errorf("expected shorthand 'T', got %q", flag.Shorthand)
		}
	})

	t.Run("has timeout flag", func(t *testing.T) {
		t.Parallel()
		flag := cmd.Flags().Lookup("timeout")
		if flag == nil {
			t.Fatal("expected timeout flag")
		}
		if flag.Shorthand != "t" {
			t.Errorf("expected shorthand 't', got %q", flag.Shorthand)
		}
	})

	t.Run("has depth flag", func(t *testing.T) {
		t.Parallel()
		flag := cmd.Flags().Lookup("depth")
		if flag == nil {
			t.Fatal("expected depth flag")
		}
		if flag.Shorthand != "d" {
			t.Errorf("expected shorthand 'd', got %q", flag.Shorthand)
		}
	})

	t.Run("has batch flag", func(t *testing.T) {
		t.Parallel()
		flag := cmd.Flags().Lookup("batch")
		if flag == nil {
			t.Fatal("expected batch flag")
		}
		if flag.Shorthand != "b" {
			t.Errorf("expected shorthand 'b', got %q", flag.Shorthand)
		}
	})

	t.Run("has config flag", func(t *testing.T) {
		t.Parallel()
		flag := cmd.Flags().Lookup("config")
		if flag == nil {
			t.Fatal("expected config flag")
		}
		if flag.Shorthand != "c" {
			t.Errorf("expected shorthand 'c', got %q", flag.Shorthand)
		}
	})

	t.Run("has json flag", func(t *testing.T) {
		t.Parallel()
		flag := cmd.Flags().Lookup("json")
		if flag == nil {
			t.Fatal("expected json flag")
		}
		if flag.Shorthand != "j" {
			t.Errorf("expected shorthand 'j', got %q", flag.Shorthand)
		}
	})

	t.Run("has output flag", func(t *testing.T) {
		t.Parallel()
		flag := cmd.Flags().Lookup("output")
		if flag == nil {
			t.Fatal("expected output flag")
		}
		if flag.Shorthand != "o" {
			t.Errorf("expected shorthand 'o', got %q", flag.Shorthand)
		}
	})

	t.Run("does not have save flag (always saves)", func(t *testing.T) {
		t.Parallel()
		flag := cmd.Flags().Lookup("save")
		if flag != nil {
			t.Error("save flag should not exist (database saving is always enabled)")
		}
	})

	t.Run("does not have db-dir flag (uses XDG)", func(t *testing.T) {
		t.Parallel()
		flag := cmd.Flags().Lookup("db-dir")
		if flag != nil {
			t.Error("db-dir flag should not exist (always uses XDG data directory)")
		}
	})
}

// TestSetupLogger tests the logger setup.
func TestSetupLogger(t *testing.T) {
	t.Parallel()

	t.Run("creates logger for verbose mode", func(t *testing.T) {
		t.Parallel()
		logger := setupLogger(true)
		if logger == nil {
			t.Error("expected non-nil logger")
		}
	})

	t.Run("creates logger for non-verbose mode", func(t *testing.T) {
		t.Parallel()
		logger := setupLogger(false)
		if logger == nil {
			t.Error("expected non-nil logger")
		}
	})
}

// TestGetVerboseFlag tests the verbose flag retrieval.
func TestGetVerboseFlag(t *testing.T) {
	t.Run("returns false when flag not set", func(t *testing.T) {
		cmd := NewScanCmd()
		result := getVerboseFlag(cmd)
		if result {
			t.Error("expected false when flag not set")
		}
	})

	t.Run("returns value from parent verbose flag", func(t *testing.T) {
		root := NewRootCmd()
		// Set verbose flag to true
		_ = root.PersistentFlags().Set("verbose", "true")

		// Get scan subcommand
		scanCmd, _, err := root.Find([]string{"scan"})
		if err != nil {
			t.Fatalf("failed to find scan command: %v", err)
		}

		result := getVerboseFlag(scanCmd)
		if !result {
			t.Error("expected true from parent verbose flag")
		}
	})
}

// TestBuildConfig tests configuration building from flags.
func TestBuildConfig(t *testing.T) {
	t.Run("builds config with default values", func(t *testing.T) {
		cmd := NewScanCmd()
		cfg, err := buildConfig(cmd, []string{"test.onion"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg == nil {
			t.Fatal("expected non-nil config")
		}
		if len(cfg.Targets) != 1 || cfg.Targets[0] != "test.onion" {
			t.Errorf("expected targets [test.onion], got %v", cfg.Targets)
		}
		if cfg.UseExternalTor {
			t.Error("expected UseExternalTor to be false")
		}
	})

	t.Run("builds config with external tor", func(t *testing.T) {
		cmd := NewScanCmd()
		_ = cmd.Flags().Set("external-tor", "127.0.0.1:9150")
		cfg, err := buildConfig(cmd, []string{"test.onion"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !cfg.UseExternalTor {
			t.Error("expected UseExternalTor to be true")
		}
		if cfg.TorProxyAddress != "127.0.0.1:9150" {
			t.Errorf("expected TorProxyAddress '127.0.0.1:9150', got %q", cfg.TorProxyAddress)
		}
	})

	t.Run("builds config with custom depth", func(t *testing.T) {
		cmd := NewScanCmd()
		_ = cmd.Flags().Set("depth", "50")
		cfg, err := buildConfig(cmd, []string{"test.onion"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.CrawlDepth != 50 {
			t.Errorf("expected CrawlDepth 50, got %d", cfg.CrawlDepth)
		}
	})

	t.Run("builds config with custom batch size", func(t *testing.T) {
		cmd := NewScanCmd()
		_ = cmd.Flags().Set("batch", "5")
		cfg, err := buildConfig(cmd, []string{"test.onion"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.BatchSize != 5 {
			t.Errorf("expected BatchSize 5, got %d", cfg.BatchSize)
		}
	})

	t.Run("builds config with JSON flag", func(t *testing.T) {
		cmd := NewScanCmd()
		_ = cmd.Flags().Set("json", "true")
		cfg, err := buildConfig(cmd, []string{"test.onion"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !cfg.JSONReport {
			t.Error("expected JSONReport to be true")
		}
	})

	t.Run("builds config with multiple targets", func(t *testing.T) {
		cmd := NewScanCmd()
		cfg, err := buildConfig(cmd, []string{"site1.onion", "site2.onion", "site3.onion"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(cfg.Targets) != 3 {
			t.Errorf("expected 3 targets, got %d", len(cfg.Targets))
		}
	})

	t.Run("builds config with valid config file", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "onionscan.yaml")

		// Create a valid config file
		content := []byte(`
defaults:
  depth: 10
sites:
  test.onion:
    cookie: session=xyz
`)
		if err := os.WriteFile(configPath, content, 0o600); err != nil {
			t.Fatalf("failed to write config: %v", err)
		}

		cmd := NewScanCmd()
		_ = cmd.Flags().Set("config", configPath)
		cfg, err := buildConfig(cmd, []string{"test.onion"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.SiteConfigs == nil {
			t.Fatal("expected SiteConfigs to be loaded")
		}
		if cfg.SiteConfigs.Defaults.Depth != 10 {
			t.Errorf("expected default depth 10, got %d", cfg.SiteConfigs.Defaults.Depth)
		}
	})

	t.Run("returns error for invalid config file", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "invalid.yaml")

		// Create an invalid config file
		content := []byte(`{invalid yaml`)
		if err := os.WriteFile(configPath, content, 0o600); err != nil {
			t.Fatalf("failed to write config: %v", err)
		}

		cmd := NewScanCmd()
		_ = cmd.Flags().Set("config", configPath)
		_, err := buildConfig(cmd, []string{"test.onion"})
		if err == nil {
			t.Fatal("expected error for invalid config file")
		}
	})

	t.Run("builds config with output file", func(t *testing.T) {
		cmd := NewScanCmd()
		_ = cmd.Flags().Set("output", "/tmp/report.json")
		cfg, err := buildConfig(cmd, []string{"test.onion"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.ReportFile != "/tmp/report.json" {
			t.Errorf("expected ReportFile '/tmp/report.json', got %q", cfg.ReportFile)
		}
	})
}

// TestGetSiteConfig tests site configuration retrieval.
func TestGetSiteConfig(t *testing.T) {
	t.Parallel()

	t.Run("returns empty config for nil SiteConfigs", func(t *testing.T) {
		t.Parallel()
		cfg := &config.Config{
			SiteConfigs: nil,
		}
		result := getSiteConfig(cfg, "test.onion")
		if result.Cookie != "" {
			t.Error("expected empty cookie")
		}
	})

	t.Run("returns exact match config", func(t *testing.T) {
		t.Parallel()
		cfg := &config.Config{
			SiteConfigs: &config.File{
				Sites: map[string]config.SiteConfig{
					"test.onion": {
						Cookie: "session=abc",
						Depth:  50,
					},
				},
			},
		}
		result := getSiteConfig(cfg, "test.onion")
		if result.Cookie != "session=abc" {
			t.Errorf("expected cookie 'session=abc', got %q", result.Cookie)
		}
		if result.Depth != 50 {
			t.Errorf("expected depth 50, got %d", result.Depth)
		}
	})

	t.Run("returns config without protocol prefix", func(t *testing.T) {
		t.Parallel()
		cfg := &config.Config{
			SiteConfigs: &config.File{
				Sites: map[string]config.SiteConfig{
					"test.onion": {
						Cookie: "session=abc",
					},
				},
			},
		}
		result := getSiteConfig(cfg, "http://test.onion")
		if result.Cookie != "session=abc" {
			t.Errorf("expected cookie 'session=abc', got %q", result.Cookie)
		}
	})

	t.Run("returns config without https prefix", func(t *testing.T) {
		t.Parallel()
		cfg := &config.Config{
			SiteConfigs: &config.File{
				Sites: map[string]config.SiteConfig{
					"test.onion": {
						Cookie: "session=xyz",
					},
				},
			},
		}
		result := getSiteConfig(cfg, "https://test.onion")
		if result.Cookie != "session=xyz" {
			t.Errorf("expected cookie 'session=xyz', got %q", result.Cookie)
		}
	})

	t.Run("returns defaults when no site match", func(t *testing.T) {
		t.Parallel()
		cfg := &config.Config{
			SiteConfigs: &config.File{
				Defaults: config.SiteConfig{
					Cookie: "default=cookie",
				},
				Sites: map[string]config.SiteConfig{},
			},
		}
		result := getSiteConfig(cfg, "other.onion")
		if result.Cookie != "default=cookie" {
			t.Errorf("expected cookie 'default=cookie', got %q", result.Cookie)
		}
	})
}

// TestMergeSiteConfig tests site configuration merging.
func TestMergeSiteConfig(t *testing.T) {
	t.Parallel()

	t.Run("override with cookie", func(t *testing.T) {
		t.Parallel()
		defaults := config.SiteConfig{
			Cookie: "default",
		}
		override := config.SiteConfig{
			Cookie: "override",
		}
		result := mergeSiteConfig(defaults, override)
		if result.Cookie != "override" {
			t.Errorf("expected cookie 'override', got %q", result.Cookie)
		}
	})

	t.Run("keeps default when override empty", func(t *testing.T) {
		t.Parallel()
		defaults := config.SiteConfig{
			Cookie: "default",
		}
		override := config.SiteConfig{}
		result := mergeSiteConfig(defaults, override)
		if result.Cookie != "default" {
			t.Errorf("expected cookie 'default', got %q", result.Cookie)
		}
	})

	t.Run("override with depth", func(t *testing.T) {
		t.Parallel()
		defaults := config.SiteConfig{
			Depth: 100,
		}
		override := config.SiteConfig{
			Depth: 50,
		}
		result := mergeSiteConfig(defaults, override)
		if result.Depth != 50 {
			t.Errorf("expected depth 50, got %d", result.Depth)
		}
	})

	t.Run("keeps default depth when override zero", func(t *testing.T) {
		t.Parallel()
		defaults := config.SiteConfig{
			Depth: 100,
		}
		override := config.SiteConfig{
			Depth: 0,
		}
		result := mergeSiteConfig(defaults, override)
		if result.Depth != 100 {
			t.Errorf("expected depth 100, got %d", result.Depth)
		}
	})

	t.Run("merges headers", func(t *testing.T) {
		t.Parallel()
		defaults := config.SiteConfig{
			Headers: map[string]string{
				"X-Default": "value1",
			},
		}
		override := config.SiteConfig{
			Headers: map[string]string{
				"X-Override": "value2",
			},
		}
		result := mergeSiteConfig(defaults, override)
		if result.Headers["X-Default"] != "value1" {
			t.Error("expected X-Default header to be preserved")
		}
		if result.Headers["X-Override"] != "value2" {
			t.Error("expected X-Override header to be added")
		}
	})

	t.Run("creates headers map when default is nil", func(t *testing.T) {
		t.Parallel()
		defaults := config.SiteConfig{}
		override := config.SiteConfig{
			Headers: map[string]string{
				"X-New": "value",
			},
		}
		result := mergeSiteConfig(defaults, override)
		if result.Headers["X-New"] != "value" {
			t.Error("expected X-New header to be set")
		}
	})

	t.Run("override ignorePatterns", func(t *testing.T) {
		t.Parallel()
		defaults := config.SiteConfig{
			IgnorePatterns: []string{"*.js"},
		}
		override := config.SiteConfig{
			IgnorePatterns: []string{"*.css"},
		}
		result := mergeSiteConfig(defaults, override)
		if len(result.IgnorePatterns) != 1 || result.IgnorePatterns[0] != "*.css" {
			t.Errorf("expected ignorePatterns [*.css], got %v", result.IgnorePatterns)
		}
	})

	t.Run("override followPatterns", func(t *testing.T) {
		t.Parallel()
		defaults := config.SiteConfig{
			FollowPatterns: []string{"/pages/*"},
		}
		override := config.SiteConfig{
			FollowPatterns: []string{"/blog/*"},
		}
		result := mergeSiteConfig(defaults, override)
		if len(result.FollowPatterns) != 1 || result.FollowPatterns[0] != "/blog/*" {
			t.Errorf("expected followPatterns [/blog/*], got %v", result.FollowPatterns)
		}
	})
}

// TestOutputReport tests the report output functionality.
func TestOutputReport(t *testing.T) {
	t.Run("outputs JSON report to file", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "report.json")

		cfg := &config.Config{
			JSONReport: true,
			ReportFile: outputPath,
		}

		report := model.NewOnionScanReport("test.onion")
		report.WebDetected = true

		err := outputReport(cfg, report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify file exists
		if _, err := os.Stat(outputPath); os.IsNotExist(err) {
			t.Error("expected output file to be created")
		}

		// Verify JSON content
		content, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(content, &result); err != nil {
			t.Fatalf("failed to parse JSON: %v", err)
		}

		if result["hidden_service"] != "test.onion" {
			t.Errorf("expected hidden_service 'test.onion', got %v", result["hidden_service"])
		}
	})

	t.Run("creates parent directories", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "subdir", "nested", "report.json")

		cfg := &config.Config{
			JSONReport: true,
			ReportFile: outputPath,
		}

		report := model.NewOnionScanReport("test.onion")

		err := outputReport(cfg, report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if _, err := os.Stat(outputPath); os.IsNotExist(err) {
			t.Error("expected output file to be created in nested directory")
		}
	})

	t.Run("outputs text report to file", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "report.txt")

		cfg := &config.Config{
			JSONReport: false,
			ReportFile: outputPath,
		}

		report := model.NewOnionScanReport("test.onion")

		err := outputReport(cfg, report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify file exists
		if _, err := os.Stat(outputPath); os.IsNotExist(err) {
			t.Error("expected output file to be created")
		}

		// Verify text content
		content, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}

		if !bytes.Contains(content, []byte("test.onion")) {
			t.Error("expected report to contain onion address")
		}
	})

	t.Run("outputs to stdout when no file specified", func(t *testing.T) {
		cfg := &config.Config{
			JSONReport: false,
			ReportFile: "",
		}

		report := model.NewOnionScanReport("test.onion")

		// This should not fail - just outputs to stdout
		err := outputReport(cfg, report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("initializes SimpleReport if nil", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "report.txt")

		cfg := &config.Config{
			JSONReport: false,
			ReportFile: outputPath,
		}

		report := model.NewOnionScanReport("test.onion")
		report.SimpleReport = nil

		err := outputReport(cfg, report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if report.SimpleReport == nil {
			t.Error("expected SimpleReport to be initialized")
		}
	})
}

// TestSaveScanReport tests the saveScanReport function.
func TestSaveScanReport(t *testing.T) {
	t.Parallel()

	// Create a logger for testing
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx := context.Background()

	t.Run("returns nil when db is nil", func(t *testing.T) {
		t.Parallel()

		report := model.NewOnionScanReport("test.onion")
		err := saveScanReport(ctx, nil, report, logger)
		if err != nil {
			t.Errorf("expected nil error when db is nil, got %v", err)
		}
	})

	t.Run("saves report to database", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		db, err := database.Open(tmpDir, database.DefaultOptions())
		if err != nil {
			t.Fatalf("failed to open database: %v", err)
		}
		defer db.Close()

		report := model.NewOnionScanReport("save-test.onion")
		report.WebDetected = true

		err = saveScanReport(ctx, db, report, logger)
		if err != nil {
			t.Fatalf("saveScanReport() error = %v", err)
		}

		// Verify report was saved
		saved, err := db.GetLatestScanReport(ctx, "save-test.onion")
		if err != nil {
			t.Fatalf("failed to get saved report: %v", err)
		}
		if saved == nil {
			t.Fatal("expected report to be saved")
		}
		if saved.HiddenService != "save-test.onion" {
			t.Errorf("expected hidden service 'save-test.onion', got %q", saved.HiddenService)
		}
	})

	t.Run("initializes SimpleReport before saving", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		db, err := database.Open(tmpDir, database.DefaultOptions())
		if err != nil {
			t.Fatalf("failed to open database: %v", err)
		}
		defer db.Close()

		report := model.NewOnionScanReport("simplereport-test.onion")
		report.SimpleReport = nil // Ensure it's nil

		err = saveScanReport(ctx, db, report, logger)
		if err != nil {
			t.Fatalf("saveScanReport() error = %v", err)
		}

		// Verify SimpleReport was initialized
		if report.SimpleReport == nil {
			t.Error("expected SimpleReport to be initialized")
		}
	})
}

// TestRunScanNoTargets tests that runScan returns error when no targets provided.
func TestRunScanNoTargets(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := config.NewConfig()
	cfg.Targets = []string{} // No targets
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	err := runScan(ctx, cfg, logger)
	if err == nil {
		t.Error("expected error for no targets")
	}
	if err.Error() != "no targets provided (specify one or more onion addresses as arguments)" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestRunScanInvalidTarget tests that runScan returns error for invalid onion address.
func TestRunScanInvalidTarget(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := config.NewConfig()
	cfg.Targets = []string{"invalid-address"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	err := runScan(ctx, cfg, logger)
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

// TestRunScanWithContextCancellation tests that runScan handles context cancellation.
func TestRunScanWithContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	cfg := config.NewConfig()
	cfg.Targets = []string{"p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion"}
	cfg.UseExternalTor = true
	cfg.TorProxyAddress = "127.0.0.1:9999" // Non-existent proxy

	// Create temp directory for database
	tmpDir := t.TempDir()
	cfg.DBDir = tmpDir
	cfg.SaveToDB = true

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// This should fail early due to cancelled context or connection failure
	err := runScan(ctx, cfg, logger)
	// Either context.Canceled or connection error is acceptable
	if err == nil {
		t.Error("expected error due to cancelled context or connection failure")
	}
}

// TestRunScanCmdNoArgs tests runScanCmd with no arguments.
func TestRunScanCmdNoArgs(t *testing.T) {
	t.Parallel()

	// NewRootCmd already includes the scan subcommand
	rootCmd := NewRootCmd()
	// Execute "scan" with no args via root command
	rootCmd.SetArgs([]string{"scan"})

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for no arguments")
	}
	// The error message contains "no target specified"
	if !strings.Contains(err.Error(), "no target") {
		t.Errorf("expected 'no target' error, got: %v", err)
	}
}

// TestRunScanCmdInvalidOnionAddress tests runScanCmd with invalid onion address.
func TestRunScanCmdInvalidOnionAddress(t *testing.T) {
	t.Parallel()

	rootCmd := NewRootCmd()
	rootCmd.SetArgs([]string{"scan", "not-a-valid-onion"})

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for invalid onion address")
	}
	// Note: The validation might pass for any string, the actual Tor connection fails later.
	// This test verifies that the command at least accepts and tries to process invalid input.
}

// TestRunScanCmdConflictingFormats tests runScanCmd with both --json and --markdown.
func TestRunScanCmdConflictingFormats(t *testing.T) {
	t.Parallel()

	rootCmd := NewRootCmd()
	rootCmd.SetArgs([]string{"scan", "--json", "--markdown", "p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion"})

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for conflicting report formats")
	}
	if !strings.Contains(err.Error(), "conflicting report formats") {
		t.Errorf("expected 'conflicting report formats' error, got: %v", err)
	}
}

// Note: TestCreatePipelineForTarget is intentionally not included as it requires
// a real Tor client (nil client causes panic). This function is tested through
// integration tests with actual Tor connectivity.

// TestOutputReportVariousFormats tests outputReport with different configurations.
func TestOutputReportVariousFormats(t *testing.T) {
	t.Run("outputs to stdout when no file specified", func(t *testing.T) {
		cfg := &config.Config{
			JSONReport:     false,
			MarkdownReport: false,
			ReportFile:     "",
		}
		report := model.NewOnionScanReport("test.onion")
		report.SimpleReport = model.NewSimpleReport(report)

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := outputReport(cfg, report)

		w.Close()
		os.Stdout = oldStdout

		if err != nil {
			t.Fatalf("outputReport() error = %v", err)
		}

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		r.Close()
		output := buf.String()

		if output == "" {
			t.Error("expected non-empty output")
		}
	})

	t.Run("outputs JSON format", func(t *testing.T) {
		cfg := &config.Config{
			JSONReport:     true,
			MarkdownReport: false,
			ReportFile:     "",
		}
		report := model.NewOnionScanReport("test.onion")
		report.SimpleReport = model.NewSimpleReport(report)

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := outputReport(cfg, report)

		w.Close()
		os.Stdout = oldStdout

		if err != nil {
			t.Fatalf("outputReport() error = %v", err)
		}

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		r.Close()
		output := buf.String()

		// Verify it's valid JSON
		var jsonReport model.OnionScanReport
		if err := json.Unmarshal([]byte(output), &jsonReport); err != nil {
			t.Errorf("expected valid JSON output, got error: %v", err)
		}
	})

	t.Run("outputs Markdown format", func(t *testing.T) {
		cfg := &config.Config{
			JSONReport:     false,
			MarkdownReport: true,
			ReportFile:     "",
		}
		report := model.NewOnionScanReport("test.onion")
		report.SimpleReport = model.NewSimpleReport(report)

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := outputReport(cfg, report)

		w.Close()
		os.Stdout = oldStdout

		if err != nil {
			t.Fatalf("outputReport() error = %v", err)
		}

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		r.Close()
		output := buf.String()

		// Verify it contains Markdown header
		if len(output) == 0 {
			t.Error("expected non-empty Markdown output")
		}
	})

	t.Run("outputs to file", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputFile := filepath.Join(tmpDir, "report.txt")

		cfg := &config.Config{
			JSONReport:     false,
			MarkdownReport: false,
			ReportFile:     outputFile,
		}
		report := model.NewOnionScanReport("test.onion")
		report.SimpleReport = model.NewSimpleReport(report)

		err := outputReport(cfg, report)
		if err != nil {
			t.Fatalf("outputReport() error = %v", err)
		}

		// Verify file was created
		if _, err := os.Stat(outputFile); os.IsNotExist(err) {
			t.Error("expected output file to be created")
		}

		// Verify file contents
		content, err := os.ReadFile(outputFile)
		if err != nil {
			t.Fatalf("failed to read output file: %v", err)
		}
		if len(content) == 0 {
			t.Error("expected non-empty file contents")
		}
	})

	t.Run("creates directory for output file", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputFile := filepath.Join(tmpDir, "subdir", "nested", "report.json")

		cfg := &config.Config{
			JSONReport:     true,
			MarkdownReport: false,
			ReportFile:     outputFile,
		}
		report := model.NewOnionScanReport("test.onion")
		report.SimpleReport = model.NewSimpleReport(report)

		err := outputReport(cfg, report)
		if err != nil {
			t.Fatalf("outputReport() error = %v", err)
		}

		// Verify directory was created
		if _, err := os.Stat(filepath.Dir(outputFile)); os.IsNotExist(err) {
			t.Error("expected directory to be created")
		}

		// Verify file was created
		if _, err := os.Stat(outputFile); os.IsNotExist(err) {
			t.Error("expected output file to be created")
		}
	})

	t.Run("initializes SimpleReport if nil", func(t *testing.T) {
		cfg := &config.Config{
			JSONReport:     false,
			MarkdownReport: false,
			ReportFile:     "",
		}
		report := model.NewOnionScanReport("test.onion")
		report.SimpleReport = nil // Explicitly set to nil

		// Capture stdout
		oldStdout := os.Stdout
		_, w, _ := os.Pipe()
		os.Stdout = w

		err := outputReport(cfg, report)

		w.Close()
		os.Stdout = oldStdout

		if err != nil {
			t.Fatalf("outputReport() error = %v", err)
		}

		// Verify SimpleReport was initialized
		if report.SimpleReport == nil {
			t.Error("expected SimpleReport to be initialized")
		}
	})
}

// TestBuildConfigWithConfigFile tests buildConfig with a configuration file.
func TestBuildConfigWithConfigFile(t *testing.T) {
	t.Parallel()

	t.Run("loads config file when specified", func(t *testing.T) {
		t.Parallel()

		// Create a temp config file
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, ".onionscan")
		configContent := `defaults:
  cookie: "default-cookie"
  depth: 50
sites:
  test.onion:
    cookie: "site-cookie"
    depth: 25
`
		if err := os.WriteFile(configFile, []byte(configContent), 0600); err != nil {
			t.Fatalf("failed to create config file: %v", err)
		}

		cmd := NewScanCmd()
		cmd.SetArgs([]string{"--config", configFile, "p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion"})

		// Parse flags
		if err := cmd.ParseFlags([]string{"--config", configFile, "p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion"}); err != nil {
			t.Fatalf("failed to parse flags: %v", err)
		}

		cfg, err := buildConfig(cmd, []string{"p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion"})
		if err != nil {
			t.Fatalf("buildConfig() error = %v", err)
		}

		if cfg.SiteConfigs == nil {
			t.Fatal("expected SiteConfigs to be loaded")
		}
		if cfg.SiteConfigs.Defaults.Depth != 50 {
			t.Errorf("expected default depth 50, got %d", cfg.SiteConfigs.Defaults.Depth)
		}
	})

	t.Run("returns error for invalid config file", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, ".onionscan")
		// Write invalid YAML
		if err := os.WriteFile(configFile, []byte("invalid: yaml: content: ["), 0600); err != nil {
			t.Fatalf("failed to create config file: %v", err)
		}

		cmd := NewScanCmd()
		if err := cmd.ParseFlags([]string{"--config", configFile}); err != nil {
			t.Fatalf("failed to parse flags: %v", err)
		}

		_, err := buildConfig(cmd, []string{"test.onion"})
		if err == nil {
			t.Error("expected error for invalid config file")
		}
	})
}

// TestBuildConfigWithExternalTor tests buildConfig with external-tor flag.
func TestBuildConfigWithExternalTor(t *testing.T) {
	t.Parallel()

	cmd := NewScanCmd()
	if err := cmd.ParseFlags([]string{"--external-tor", "127.0.0.1:9050"}); err != nil {
		t.Fatalf("failed to parse flags: %v", err)
	}

	cfg, err := buildConfig(cmd, []string{"p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion"})
	if err != nil {
		t.Fatalf("buildConfig() error = %v", err)
	}

	if !cfg.UseExternalTor {
		t.Error("expected UseExternalTor to be true")
	}
	if cfg.TorProxyAddress != "127.0.0.1:9050" {
		t.Errorf("expected TorProxyAddress '127.0.0.1:9050', got %q", cfg.TorProxyAddress)
	}
}
