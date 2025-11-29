package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nao1215/onionscan/internal/config"
	"github.com/nao1215/onionscan/internal/database"
	"github.com/nao1215/onionscan/internal/model"
	"github.com/nao1215/onionscan/internal/pipeline"
	"github.com/nao1215/onionscan/internal/report"
	"github.com/nao1215/onionscan/internal/tor"
	"github.com/spf13/cobra"
)

// NewScanCmd creates the scan command.
func NewScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [onion-address]",
		Short: "Scan a Tor hidden service for security issues",
		Long: `Scan performs security auditing of Tor hidden services (.onion addresses).

It connects through Tor, crawls the hidden service, and analyzes it for:
- Deanonymization risks (IP leaks, external resources)
- Identity correlation (analytics IDs, crypto addresses, emails)
- Security misconfigurations (headers, cookies, certificates)
- Malicious content (obfuscated JS, hidden iframes, redirects)

Examples:
  # Scan a single onion service
  onionscan scan exampleonion.onion

  # Scan multiple onion services
  onionscan scan site1.onion site2.onion site3.onion

  # Use external Tor proxy instead of embedded daemon
  onionscan scan --external-tor 127.0.0.1:9150 exampleonion.onion

  # Output JSON report
  onionscan scan --json exampleonion.onion

  # Use a custom configuration file
  onionscan scan -c myconfig.yaml exampleonion.onion

Configuration file (.onionscan) example:
  sites:
    exampleonion.onion:
      cookie: "session_id=abc123"
      headers:
        Authorization: "Bearer token"
    anotheronion.onion:
      cookie: "auth=xyz789"
      depth: 50`,
		Args: cobra.ArbitraryArgs,
		RunE: runScanCmd,
	}

	// Tor connection flags
	cmd.Flags().StringP("external-tor", "e", "",
		"Use external Tor proxy at specified address (e.g., 127.0.0.1:9150)")
	cmd.Flags().DurationP("tor-timeout", "T", config.DefaultTorStartupTimeout,
		"Timeout for embedded Tor startup")

	// Scan behavior flags
	cmd.Flags().DurationP("timeout", "t", config.DefaultTimeout,
		"Connection timeout for each request")
	cmd.Flags().IntP("depth", "d", config.DefaultCrawlDepth,
		"Maximum crawl recursion depth")
	cmd.Flags().IntP("max-pages", "p", config.DefaultMaxPages,
		"Maximum number of pages to crawl per hidden service")

	// Batch scanning flags
	cmd.Flags().IntP("batch", "b", config.DefaultBatchSize,
		"Number of concurrent scans")

	// Configuration file
	cmd.Flags().StringP("config", "c", "",
		"Configuration file path (default: .onionscan in current or home directory)")

	// Report flags
	cmd.Flags().BoolP("json", "j", false,
		"Output JSON report (mutually exclusive with --markdown)")
	cmd.Flags().BoolP("markdown", "m", false,
		"Output Markdown report (mutually exclusive with --json)")
	cmd.Flags().StringP("output", "o", "",
		"Write report to specified file path (creates directories if needed)")

	return cmd
}

// runScanCmd executes the scan command.
func runScanCmd(cmd *cobra.Command, args []string) error {
	// Build config from flags
	cfg, err := buildConfig(cmd, args)
	if err != nil {
		return err
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	// Set up structured logging
	verbose := getVerboseFlag(cmd)
	logger := setupLogger(verbose)
	slog.SetDefault(logger)

	// Set up context with signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("received shutdown signal, cancelling...")
		cancel()
	}()

	return runScan(ctx, cfg, logger)
}

// getVerboseFlag retrieves the verbose flag from the command or its parent.
func getVerboseFlag(cmd *cobra.Command) bool {
	verbose, err := cmd.Flags().GetBool("verbose")
	if err != nil {
		verbose, err = cmd.Root().PersistentFlags().GetBool("verbose")
		if err != nil {
			return false
		}
	}
	return verbose
}

// buildConfig creates a Config from cobra command flags.
func buildConfig(cmd *cobra.Command, args []string) (*config.Config, error) {
	cfg := config.NewConfig()

	// Get flag values
	var err error

	externalTor, err := cmd.Flags().GetString("external-tor")
	if err != nil {
		return nil, err
	}
	if externalTor != "" {
		cfg.UseExternalTor = true
		cfg.TorProxyAddress = externalTor
	}

	cfg.TorStartupTimeout, err = cmd.Flags().GetDuration("tor-timeout")
	if err != nil {
		return nil, err
	}

	cfg.Timeout, err = cmd.Flags().GetDuration("timeout")
	if err != nil {
		return nil, err
	}

	cfg.CrawlDepth, err = cmd.Flags().GetInt("depth")
	if err != nil {
		return nil, err
	}

	cfg.MaxPages, err = cmd.Flags().GetInt("max-pages")
	if err != nil {
		return nil, err
	}

	cfg.BatchSize, err = cmd.Flags().GetInt("batch")
	if err != nil {
		return nil, err
	}

	cfg.ConfigFilePath, err = cmd.Flags().GetString("config")
	if err != nil {
		return nil, err
	}

	// Load site-specific configurations from config file
	// If user explicitly specified a config file path, error if not found.
	// If no path specified, silently use empty config if no file found.
	explicitConfigPath := cfg.ConfigFilePath != ""
	configPath := config.FindConfigFile(cfg.ConfigFilePath)

	if configPath != "" {
		cfg.SiteConfigs, err = config.LoadConfigFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load config file %s: %w", configPath, err)
		}
	} else if explicitConfigPath {
		// User explicitly specified a config file that doesn't exist
		return nil, fmt.Errorf("configuration file not found: %s", cfg.ConfigFilePath)
	} else {
		// Use empty config if no file found and user didn't explicitly specify one
		cfg.SiteConfigs = &config.File{
			Sites: make(map[string]config.SiteConfig),
		}
	}

	cfg.JSONReport, err = cmd.Flags().GetBool("json")
	if err != nil {
		return nil, err
	}

	cfg.MarkdownReport, err = cmd.Flags().GetBool("markdown")
	if err != nil {
		return nil, err
	}

	cfg.ReportFile, err = cmd.Flags().GetString("output")
	if err != nil {
		return nil, err
	}

	// Always save to database using XDG data directory
	cfg.SaveToDB = true
	cfg.DBDir = config.XDGDataDir()

	// Get positional arguments (onion addresses)
	cfg.Targets = args

	return cfg, nil
}

// setupLogger creates a structured logger based on verbosity setting.
func setupLogger(verbose bool) *slog.Logger {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelDebug
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	handler := slog.NewTextHandler(os.Stderr, opts)
	return slog.New(handler)
}

// runScan executes the scan.
func runScan(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
	if len(cfg.Targets) == 0 {
		return errors.New("no targets provided (specify one or more onion addresses as arguments)")
	}

	logger.Info("starting scan",
		"targets", cfg.Targets,
		"useExternalTor", cfg.UseExternalTor,
		"batchSize", cfg.BatchSize,
		"saveToDB", cfg.SaveToDB,
	)

	// Open database connection if saving is enabled
	var db *database.CrawlDB
	if cfg.SaveToDB {
		var err error
		db, err = database.Open(cfg.DBDir, database.DefaultOptions())
		if err != nil {
			return fmt.Errorf("failed to open database: %w", err)
		}
		defer db.Close()
		logger.Info("database opened", "dir", cfg.DBDir)
	}

	// Validate and normalize all onion addresses
	for i, target := range cfg.Targets {
		normalized, err := tor.NormalizeAddress(target)
		if err != nil {
			return fmt.Errorf("invalid onion address %q: %w", target, err)
		}
		cfg.Targets[i] = normalized
	}

	var client *tor.Client
	var embeddedTor *tor.EmbeddedTor

	if cfg.UseExternalTor {
		// Use external Tor proxy
		var err error
		client, err = tor.NewClient(cfg.TorProxyAddress, cfg.Timeout)
		if err != nil {
			return fmt.Errorf("failed to create Tor client: %w", err)
		}

		status := client.CheckConnection(ctx)
		if status != tor.ProxyStatusOK {
			return fmt.Errorf("tor proxy check failed: %s (make sure Tor is running at %s)",
				status, cfg.TorProxyAddress)
		}

		logger.Info("Tor proxy connection verified",
			"address", cfg.TorProxyAddress,
		)
	} else {
		// Start embedded Tor daemon (default)
		var err error
		client, embeddedTor, err = startEmbeddedTor(ctx, cfg, logger)
		if err != nil {
			return err
		}
		// Ensure cleanup on exit
		defer func() {
			logger.Info("stopping embedded Tor daemon...")
			if err := embeddedTor.Stop(); err != nil {
				logger.Error("failed to stop embedded Tor", "error", err)
			}
		}()
	}

	// Use batch processor for parallel scanning if multiple targets
	if len(cfg.Targets) > 1 && cfg.BatchSize > 1 {
		return runBatchScan(ctx, cfg, client, db, logger)
	}

	// Single target or sequential scanning
	return runSequentialScan(ctx, cfg, client, db, logger)
}

// runSequentialScan scans targets one at a time.
func runSequentialScan(ctx context.Context, cfg *config.Config, client *tor.Client, db *database.CrawlDB, logger *slog.Logger) error {
	for _, target := range cfg.Targets {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Get site-specific configuration
		siteConfig := getSiteConfig(cfg, target)

		// Create pipeline with site-specific options
		p := createPipelineForTarget(client, logger, cfg, siteConfig)

		scanReport := model.NewOnionScanReport(target)

		fmt.Printf("Scanning %s...\n", target)
		startTime := time.Now()

		// Execute the pipeline
		if err := p.Execute(ctx, scanReport); err != nil {
			logger.Error("scan failed", "target", target, "error", err)
			fmt.Fprintf(os.Stderr, "Scan error for %s: %v\n", target, err)
			continue
		}

		elapsed := time.Since(startTime)
		fmt.Printf("Scan completed in %s\n\n", elapsed.Round(time.Millisecond))

		// Generate and output report
		if err := outputReport(cfg, scanReport); err != nil {
			logger.Error("report failed", "target", target, "error", err)
		}

		// Save to database if enabled
		if err := saveScanReport(ctx, db, scanReport, logger); err != nil {
			logger.Error("failed to save scan report", "target", target, "error", err)
		}
	}

	return nil
}

// runBatchScan scans multiple targets concurrently using BatchProcessor.
func runBatchScan(ctx context.Context, cfg *config.Config, client *tor.Client, db *database.CrawlDB, logger *slog.Logger) error {
	fmt.Printf("Starting batch scan of %d targets (concurrency: %d)...\n\n",
		len(cfg.Targets), cfg.BatchSize)

	startTime := time.Now()

	// Warn user about batch processing limitation
	if cfg.SiteConfigs != nil && len(cfg.SiteConfigs.Sites) > 0 {
		logger.Warn("batch processing uses default site config only; site-specific configs (cookies, headers, depth) are ignored",
			"siteCount", len(cfg.SiteConfigs.Sites))
		fmt.Fprintf(os.Stderr, "Warning: Site-specific configurations are ignored in batch mode. Use sequential mode (--batch 1) to apply per-site settings.\n\n")
	}

	// Create batch processor with pipeline factory
	bp := pipeline.NewBatchProcessor(
		func() *pipeline.Pipeline {
			// Note: For batch processing, we use default site config
			// Site-specific configs would require per-target pipeline creation
			var siteConfig config.SiteConfig
			if cfg.SiteConfigs != nil {
				siteConfig = cfg.SiteConfigs.Defaults
			}
			return createPipelineForTarget(client, logger, cfg, siteConfig)
		},
		pipeline.WithConcurrency(cfg.BatchSize),
		pipeline.WithBatchLogger(logger),
	)

	// Process with callback for streaming output
	var mu sync.Mutex
	err := bp.ProcessBatchWithCallback(ctx, cfg.Targets, func(report *model.OnionScanReport, index int) {
		mu.Lock()
		defer mu.Unlock()

		fmt.Printf("[%d/%d] Scan completed: %s\n", index+1, len(cfg.Targets), report.HiddenService)

		// Generate and output report
		if err := outputReport(cfg, report); err != nil {
			logger.Error("report failed", "target", report.HiddenService, "error", err)
		}

		// Save to database if enabled
		if err := saveScanReport(ctx, db, report, logger); err != nil {
			logger.Error("failed to save scan report", "target", report.HiddenService, "error", err)
		}
	})

	elapsed := time.Since(startTime)
	fmt.Printf("\nBatch scan completed in %s\n", elapsed.Round(time.Millisecond))

	return err
}

// getSiteConfig returns the site-specific configuration for a target.
// Falls back to defaults if no site-specific config exists.
func getSiteConfig(cfg *config.Config, target string) config.SiteConfig {
	if cfg.SiteConfigs == nil {
		return config.SiteConfig{}
	}

	// Try exact match first
	if siteConfig, ok := cfg.SiteConfigs.Sites[target]; ok {
		return mergeSiteConfig(cfg.SiteConfigs.Defaults, siteConfig)
	}

	// Try without protocol prefix
	cleanTarget := target
	for _, prefix := range []string{"http://", "https://"} {
		cleanTarget = strings.TrimPrefix(cleanTarget, prefix)
	}
	if siteConfig, ok := cfg.SiteConfigs.Sites[cleanTarget]; ok {
		return mergeSiteConfig(cfg.SiteConfigs.Defaults, siteConfig)
	}

	return cfg.SiteConfigs.Defaults
}

// mergeSiteConfig merges default config with site-specific overrides.
func mergeSiteConfig(defaults, override config.SiteConfig) config.SiteConfig {
	result := defaults

	// Override with non-zero values
	if override.Cookie != "" {
		result.Cookie = override.Cookie
	}
	if override.Depth > 0 {
		result.Depth = override.Depth
	}
	if len(override.Headers) > 0 {
		if result.Headers == nil {
			result.Headers = make(map[string]string)
		}
		for k, v := range override.Headers {
			result.Headers[k] = v
		}
	}
	if len(override.IgnorePatterns) > 0 {
		result.IgnorePatterns = override.IgnorePatterns
	}
	if len(override.FollowPatterns) > 0 {
		result.FollowPatterns = override.FollowPatterns
	}

	return result
}

// createPipelineForTarget creates a pipeline with the given configuration.
func createPipelineForTarget(client *tor.Client, logger *slog.Logger, cfg *config.Config, siteConfig config.SiteConfig) *pipeline.Pipeline {
	pipelineOpts := []pipeline.Option{
		pipeline.WithLogger(logger),
		pipeline.WithContinueOnError(true),
	}

	// Determine crawl depth (site-specific overrides global)
	crawlDepth := cfg.CrawlDepth
	if siteConfig.Depth > 0 {
		crawlDepth = siteConfig.Depth
	}
	maxPages := cfg.MaxPages

	configOpts := []pipeline.DefaultPipelineOption{
		pipeline.WithPipelineCrawlDepth(crawlDepth),
		pipeline.WithPipelineCrawlMaxPages(maxPages),
	}

	// Add cookie if configured
	if siteConfig.Cookie != "" {
		configOpts = append(configOpts, pipeline.WithPipelineCookie(siteConfig.Cookie))
	}

	// Add custom headers if configured
	if len(siteConfig.Headers) > 0 {
		configOpts = append(configOpts, pipeline.WithPipelineHeaders(siteConfig.Headers))
	}

	// Add URL pattern filtering if configured
	if len(siteConfig.IgnorePatterns) > 0 {
		configOpts = append(configOpts, pipeline.WithPipelineIgnorePatterns(siteConfig.IgnorePatterns))
	}
	if len(siteConfig.FollowPatterns) > 0 {
		configOpts = append(configOpts, pipeline.WithPipelineFollowPatterns(siteConfig.FollowPatterns))
	}

	return pipeline.DefaultPipeline(client, pipelineOpts, configOpts...)
}

// outputReport outputs the scan report in the requested format.
func outputReport(cfg *config.Config, scanReport *model.OnionScanReport) error {
	// Generate simple report if needed
	if scanReport.SimpleReport == nil {
		scanReport.SimpleReport = model.NewSimpleReport(scanReport)
	}

	// Determine output destination
	var output *os.File
	if cfg.ReportFile != "" {
		// Create directories if they don't exist
		dir := filepath.Dir(cfg.ReportFile)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0750); err != nil {
				return fmt.Errorf("failed to create output directory: %w", err)
			}
		}

		// Create/overwrite the output file with secure permissions (0600)
		// Reports may contain sensitive information that should only be readable by the owner
		f, err := os.OpenFile(cfg.ReportFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		output = f
	} else {
		output = os.Stdout
	}

	// JSON output (detailed report with all data)
	if cfg.JSONReport {
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		return encoder.Encode(scanReport)
	}

	// Markdown output
	if cfg.MarkdownReport {
		writer := report.NewMarkdownWriter(output)
		_, err := writer.Write(scanReport)
		return err
	}

	// Human-readable report (default)
	writer := report.NewSimpleWriter(output)
	_, err := writer.Write(scanReport)
	return err
}

// startEmbeddedTor starts an embedded Tor daemon using tornago.
// Returns the Tor client and embedded Tor manager on success.
func startEmbeddedTor(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*tor.Client, *tor.EmbeddedTor, error) {
	fmt.Println("Starting embedded Tor daemon...")
	fmt.Printf("This may take 1-3 minutes while Tor bootstraps and connects to the network.\n\n")

	embeddedTor := tor.NewEmbeddedTor(
		tor.WithStartupTimeout(cfg.TorStartupTimeout),
	)

	// Start the embedded Tor daemon
	if err := embeddedTor.Start(ctx); err != nil {
		return nil, nil, fmt.Errorf("failed to start embedded Tor: %w", err)
	}

	logger.Info("embedded Tor daemon started",
		"socksAddr", embeddedTor.SocksAddr(),
		"controlAddr", embeddedTor.ControlAddr(),
	)

	fmt.Printf("Embedded Tor daemon started successfully!\n")
	fmt.Printf("SOCKS proxy: %s\n\n", embeddedTor.SocksAddr())

	// Create a client using the embedded Tor's SOCKS proxy
	client, err := embeddedTor.NewClient(cfg.Timeout)
	if err != nil {
		_ = embeddedTor.Stop() //nolint:errcheck // Best effort cleanup
		return nil, nil, fmt.Errorf("failed to create Tor client: %w", err)
	}

	// Verify the connection
	status := client.CheckConnection(ctx)
	if status != tor.ProxyStatusOK {
		_ = embeddedTor.Stop() //nolint:errcheck // Best effort cleanup
		return nil, nil, fmt.Errorf("embedded Tor proxy check failed: %s", status)
	}

	return client, embeddedTor, nil
}

// saveScanReport saves the scan report to the database if enabled.
// If db is nil, this function is a no-op.
func saveScanReport(ctx context.Context, db *database.CrawlDB, report *model.OnionScanReport, logger *slog.Logger) error {
	if db == nil {
		return nil
	}

	// Ensure SimpleReport is generated before saving
	if report.SimpleReport == nil {
		report.SimpleReport = model.NewSimpleReport(report)
	}

	if err := db.SaveScanReport(ctx, report); err != nil {
		return fmt.Errorf("failed to save scan report: %w", err)
	}

	logger.Info("scan report saved to database", "target", report.HiddenService)
	return nil
}
