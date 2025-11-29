package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nao1215/onionscan/internal/config"
	"github.com/nao1215/onionscan/internal/database"
	"github.com/nao1215/onionscan/internal/model"
	"github.com/nao1215/onionscan/internal/tor"
	"github.com/nao1215/tornago"
)

// skipIfShort skips the test if -short flag is set.
// Integration tests with real Tor are slow and should be skipped in short mode.
func skipIfShort(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode (requires real Tor, takes 2-5 minutes)")
	}
}

// skipIfNoTor skips the test if the Tor binary is not available.
// This allows tests to pass on CI environments without Tor installed.
func skipIfNoTor(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("tor"); err != nil {
		t.Skip("skipping integration test: Tor binary not found (install tor to run integration tests)")
	}
}

// testOnionServer holds the test infrastructure.
type testOnionServer struct {
	torProcess    *tornago.TorProcess
	controlClient *tornago.ControlClient
	httpServer    *http.Server
	listener      net.Listener
	onionAddress  string
}

// startTestOnionServer starts a Tor daemon, creates a hidden service, and starts an HTTP server.
// This creates a complete test environment with a real .onion address.
//
//nolint:noctx // context is used for Tor operations, not for net.Listen
func startTestOnionServer(ctx context.Context, t *testing.T) *testOnionServer {
	t.Helper()

	// Start local HTTP server first
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	localPort := listener.Addr().(*net.TCPAddr).Port
	t.Logf("Local HTTP server listening on port %d", localPort)

	// Create test HTTP server with some interesting content
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Test Onion Service</title></head>
<body>
<h1>Welcome to Test Onion Service</h1>
<p>This is a test page for OnionScan integration testing.</p>
<a href="/about">About</a>
<a href="/contact">Contact</a>
<p>Contact: test@example.com</p>
<p>Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa</p>
</body>
</html>`))
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>About - Test Onion Service</title></head>
<body>
<h1>About Us</h1>
<p>This is the about page.</p>
<a href="/">Home</a>
</body>
</html>`))
	})
	mux.HandleFunc("/contact", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Contact - Test Onion Service</title></head>
<body>
<h1>Contact Us</h1>
<p>Email: admin@example.onion</p>
<a href="/">Home</a>
</body>
</html>`))
	})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Logf("HTTP server error: %v", err)
		}
	}()

	// Start Tor daemon
	t.Log("Starting Tor daemon...")
	launchCfg, err := tornago.NewTorLaunchConfig(
		tornago.WithTorSocksAddr(":0"),
		tornago.WithTorControlAddr(":0"),
		tornago.WithTorStartupTimeout(5*time.Minute),
	)
	if err != nil {
		listener.Close()
		server.Close()
		t.Fatalf("failed to create Tor launch config: %v", err)
	}

	torProcess, err := tornago.StartTorDaemon(launchCfg)
	if err != nil {
		listener.Close()
		server.Close()
		t.Fatalf("failed to start Tor daemon: %v", err)
	}
	t.Logf("Tor daemon started: SOCKS=%s, Control=%s", torProcess.SocksAddr(), torProcess.ControlAddr())

	// Create control client using cookie authentication
	cookiePath := filepath.Join(torProcess.DataDir(), "control_auth_cookie")
	auth := tornago.ControlAuthFromCookie(cookiePath)
	controlClient, err := tornago.NewControlClient(torProcess.ControlAddr(), auth, 30*time.Second)
	if err != nil {
		torProcess.Stop()
		listener.Close()
		server.Close()
		t.Fatalf("failed to create control client: %v", err)
	}

	if err := controlClient.Authenticate(); err != nil {
		controlClient.Close()
		torProcess.Stop()
		listener.Close()
		server.Close()
		t.Fatalf("failed to authenticate: %v", err)
	}

	// Create hidden service
	t.Log("Creating hidden service...")
	hsCfg, err := tornago.NewHiddenServiceConfig(
		tornago.WithHiddenServicePort(80, localPort),
	)
	if err != nil {
		controlClient.Close()
		torProcess.Stop()
		listener.Close()
		server.Close()
		t.Fatalf("failed to create hidden service config: %v", err)
	}

	hs, err := controlClient.CreateHiddenService(ctx, hsCfg)
	if err != nil {
		controlClient.Close()
		torProcess.Stop()
		listener.Close()
		server.Close()
		t.Fatalf("failed to create hidden service: %v", err)
	}

	onionAddr := hs.OnionAddress()
	t.Logf("Hidden service created: %s", onionAddr)

	// Wait for the hidden service to be reachable
	t.Log("Waiting for hidden service to be reachable...")
	clientCfg, err := tornago.NewClientConfig(
		tornago.WithClientSocksAddr(torProcess.SocksAddr()),
		tornago.WithClientRequestTimeout(30*time.Second),
	)
	if err != nil {
		controlClient.Close()
		torProcess.Stop()
		listener.Close()
		server.Close()
		t.Fatalf("failed to create client config: %v", err)
	}

	client, err := tornago.NewClient(clientCfg)
	if err != nil {
		controlClient.Close()
		torProcess.Stop()
		listener.Close()
		server.Close()
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Poll until the service is reachable (may take up to 2 minutes)
	httpClient := client.HTTP()
	reachable := false
	for i := range 24 { // 24 attempts, 5 seconds each = 2 minutes max
		select {
		case <-ctx.Done():
			controlClient.Close()
			torProcess.Stop()
			listener.Close()
			server.Close()
			t.Fatalf("context cancelled while waiting for hidden service")
		default:
		}

		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+onionAddr+"/", nil)
		if reqErr != nil {
			t.Logf("Attempt %d: failed to create request: %v", i+1, reqErr)
			time.Sleep(5 * time.Second)
			continue
		}
		resp, err := httpClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				reachable = true
				t.Logf("Hidden service is reachable after %d attempts", i+1)
				break
			}
		}
		t.Logf("Attempt %d: waiting for hidden service... (err: %v)", i+1, err)
		time.Sleep(5 * time.Second)
	}

	if !reachable {
		controlClient.Close()
		torProcess.Stop()
		listener.Close()
		server.Close()
		t.Fatalf("hidden service not reachable after 2 minutes")
	}

	return &testOnionServer{
		torProcess:    torProcess,
		controlClient: controlClient,
		httpServer:    server,
		listener:      listener,
		onionAddress:  onionAddr,
	}
}

// stop cleans up all test resources.
func (s *testOnionServer) stop(t *testing.T) {
	t.Helper()
	if s.httpServer != nil {
		s.httpServer.Close()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	if s.controlClient != nil {
		s.controlClient.Close()
	}
	if s.torProcess != nil {
		s.torProcess.Stop()
	}
}

// TestIntegrationScanWithRealTor performs an integration test with a real Tor network.
// This test:
// 1. Starts a Tor daemon
// 2. Creates a hidden service with a test HTTP server
// 3. Scans the hidden service using OnionScan
// 4. Verifies the scan results
//
// Note: This test takes 3-5 minutes to complete due to Tor bootstrapping.
func TestIntegrationScanWithRealTor(t *testing.T) {
	skipIfShort(t)
	skipIfNoTor(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Start test infrastructure
	testServer := startTestOnionServer(ctx, t)
	defer testServer.stop(t)

	t.Logf("Testing with onion address: %s", testServer.onionAddress)

	// Create temp directory for database
	tmpDir := t.TempDir()
	dbDir := filepath.Join(tmpDir, "db")

	// Create config for scan
	cfg := config.NewConfig()
	cfg.Targets = []string{testServer.onionAddress}
	cfg.UseExternalTor = true
	cfg.TorProxyAddress = testServer.torProcess.SocksAddr()
	cfg.Timeout = 60 * time.Second
	cfg.CrawlDepth = 2
	cfg.BatchSize = 1
	cfg.DBDir = dbDir
	cfg.SaveToDB = true

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Run the scan
	t.Log("Running scan...")
	err := runScan(ctx, cfg, logger)
	if err != nil {
		t.Fatalf("runScan() error = %v", err)
	}

	// Verify database was created and has data
	db, err := database.Open(dbDir, database.Options{CreateIfNotExists: false, EnableWAL: true})
	if err != nil {
		t.Fatalf("failed to open database after scan: %v", err)
	}
	defer db.Close()

	// Check that scan report was saved
	reports, err := db.GetScanHistory(ctx, testServer.onionAddress)
	if err != nil {
		t.Fatalf("failed to get scan history: %v", err)
	}
	if len(reports) == 0 {
		t.Error("expected at least one scan report in database")
	}

	t.Logf("Scan completed successfully. Found %d report(s) in database.", len(reports))

	// Verify report content
	if len(reports) > 0 {
		report := reports[0]
		if report.HiddenService != testServer.onionAddress {
			t.Errorf("expected HiddenService %q, got %q", testServer.onionAddress, report.HiddenService)
		}
		if report.SimpleReport != nil {
			t.Logf("Findings: Critical=%d, High=%d, Medium=%d, Low=%d, Info=%d",
				report.SimpleReport.CriticalCount,
				report.SimpleReport.HighCount,
				report.SimpleReport.MediumCount,
				report.SimpleReport.LowCount,
				report.SimpleReport.InfoCount,
			)
		}
	}
}

// TestIntegrationScanAndCompare tests the full workflow: scan twice, then compare.
func TestIntegrationScanAndCompare(t *testing.T) {
	skipIfShort(t)
	skipIfNoTor(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Start test infrastructure
	testServer := startTestOnionServer(ctx, t)
	defer testServer.stop(t)

	t.Logf("Testing with onion address: %s", testServer.onionAddress)

	// Create temp directory for database
	tmpDir := t.TempDir()
	dbDir := filepath.Join(tmpDir, "db")

	// Create config for scan
	cfg := config.NewConfig()
	cfg.Targets = []string{testServer.onionAddress}
	cfg.UseExternalTor = true
	cfg.TorProxyAddress = testServer.torProcess.SocksAddr()
	cfg.Timeout = 60 * time.Second
	cfg.CrawlDepth = 2
	cfg.BatchSize = 1
	cfg.DBDir = dbDir
	cfg.SaveToDB = true

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Run first scan
	t.Log("Running first scan...")
	err := runScan(ctx, cfg, logger)
	if err != nil {
		t.Fatalf("first runScan() error = %v", err)
	}

	// Wait a bit and run second scan
	time.Sleep(2 * time.Second)

	t.Log("Running second scan...")
	err = runScan(ctx, cfg, logger)
	if err != nil {
		t.Fatalf("second runScan() error = %v", err)
	}

	// Now test the compare functionality
	db, err := database.Open(dbDir, database.Options{CreateIfNotExists: false, EnableWAL: true})
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	// Verify we have 2 scans
	reports, err := db.GetScanHistory(ctx, testServer.onionAddress)
	if err != nil {
		t.Fatalf("failed to get scan history: %v", err)
	}
	if len(reports) < 2 {
		t.Fatalf("expected at least 2 scan reports, got %d", len(reports))
	}

	t.Logf("Found %d scan reports. Running comparison...", len(reports))

	// Test runComparison
	err = runComparison(ctx, db, testServer.onionAddress, 0, "", false, false)
	if err != nil {
		t.Fatalf("runComparison() error = %v", err)
	}

	// Test with JSON output
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err = runComparison(ctx, db, testServer.onionAddress, 0, "", true, false)

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("runComparison() with JSON error = %v", err)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	if !strings.Contains(output, `"onion_service"`) {
		t.Errorf("expected JSON output to contain 'onion_service', got: %s", output)
	}

	t.Log("Comparison completed successfully")
}

// TestIntegrationBatchScan tests batch scanning with multiple targets.
func TestIntegrationBatchScan(t *testing.T) {
	skipIfShort(t)
	skipIfNoTor(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Start test infrastructure
	testServer := startTestOnionServer(ctx, t)
	defer testServer.stop(t)

	t.Logf("Testing with onion address: %s", testServer.onionAddress)

	// Create temp directory for database
	tmpDir := t.TempDir()
	dbDir := filepath.Join(tmpDir, "db")

	// Open database
	db, err := database.Open(dbDir, database.DefaultOptions())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	// Create config with multiple targets (same target twice for testing)
	cfg := config.NewConfig()
	cfg.Targets = []string{testServer.onionAddress, testServer.onionAddress}
	cfg.UseExternalTor = true
	cfg.TorProxyAddress = testServer.torProcess.SocksAddr()
	cfg.Timeout = 60 * time.Second
	cfg.CrawlDepth = 1
	cfg.BatchSize = 2 // Enable batch scanning
	cfg.DBDir = dbDir
	cfg.SaveToDB = true

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Create client for batch scan
	torClient, err := tor.NewClient(testServer.torProcess.SocksAddr(), cfg.Timeout)
	if err != nil {
		t.Fatalf("failed to create Tor client: %v", err)
	}

	// Run batch scan directly
	t.Log("Running batch scan...")
	err = runBatchScan(ctx, cfg, torClient, db, logger)
	if err != nil {
		t.Fatalf("runBatchScan() error = %v", err)
	}

	// Verify database has entries
	reports, err := db.GetScanHistory(ctx, testServer.onionAddress)
	if err != nil {
		t.Fatalf("failed to get scan history: %v", err)
	}
	if len(reports) < 2 {
		t.Errorf("expected at least 2 scan reports from batch scan, got %d", len(reports))
	}

	t.Logf("Batch scan completed. Found %d report(s) in database.", len(reports))
}

// TestIntegrationSequentialScan tests sequential scanning.
func TestIntegrationSequentialScan(t *testing.T) {
	skipIfShort(t)
	skipIfNoTor(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Start test infrastructure
	testServer := startTestOnionServer(ctx, t)
	defer testServer.stop(t)

	t.Logf("Testing with onion address: %s", testServer.onionAddress)

	// Create temp directory for database
	tmpDir := t.TempDir()
	dbDir := filepath.Join(tmpDir, "db")

	// Open database
	db, err := database.Open(dbDir, database.DefaultOptions())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	// Create config
	cfg := config.NewConfig()
	cfg.Targets = []string{testServer.onionAddress}
	cfg.UseExternalTor = true
	cfg.TorProxyAddress = testServer.torProcess.SocksAddr()
	cfg.Timeout = 60 * time.Second
	cfg.CrawlDepth = 2
	cfg.BatchSize = 1
	cfg.DBDir = dbDir
	cfg.SaveToDB = true

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Create Tor client
	torClient, err := tor.NewClient(testServer.torProcess.SocksAddr(), cfg.Timeout)
	if err != nil {
		t.Fatalf("failed to create Tor client: %v", err)
	}

	// Run sequential scan directly
	t.Log("Running sequential scan...")
	err = runSequentialScan(ctx, cfg, torClient, db, logger)
	if err != nil {
		t.Fatalf("runSequentialScan() error = %v", err)
	}

	// Verify database has entry
	reports, err := db.GetScanHistory(ctx, testServer.onionAddress)
	if err != nil {
		t.Fatalf("failed to get scan history: %v", err)
	}
	if len(reports) == 0 {
		t.Error("expected at least 1 scan report from sequential scan")
	}

	t.Logf("Sequential scan completed. Found %d report(s) in database.", len(reports))
}

// TestIntegrationCreatePipelineForTarget tests pipeline creation.
func TestIntegrationCreatePipelineForTarget(t *testing.T) {
	skipIfShort(t)
	skipIfNoTor(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Start test infrastructure
	testServer := startTestOnionServer(ctx, t)
	defer testServer.stop(t)

	// Create Tor client
	client, err := tor.NewClient(testServer.torProcess.SocksAddr(), 60*time.Second)
	if err != nil {
		t.Fatalf("failed to create Tor client: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Create config with various site-specific settings
	cfg := config.NewConfig()
	cfg.CrawlDepth = 5
	cfg.SiteConfigs = &config.File{
		Defaults: config.SiteConfig{
			Depth:   3,
			Cookie:  "session=test123",
			Headers: map[string]string{"X-Custom": "value"},
		},
	}

	// Test with default site config
	t.Run("with default site config", func(t *testing.T) {
		siteConfig := cfg.SiteConfigs.Defaults
		p := createPipelineForTarget(client, logger, cfg, siteConfig)
		if p == nil {
			t.Error("expected non-nil pipeline")
		}
	})

	// Test with custom site config
	t.Run("with custom site config", func(t *testing.T) {
		siteConfig := config.SiteConfig{
			Depth:          10,
			Cookie:         "custom=cookie",
			Headers:        map[string]string{"Authorization": "Bearer token"},
			IgnorePatterns: []string{"/admin/*"},
			FollowPatterns: []string{"/public/*"},
		}
		p := createPipelineForTarget(client, logger, cfg, siteConfig)
		if p == nil {
			t.Error("expected non-nil pipeline")
		}
	})

	// Test pipeline execution
	t.Run("pipeline execution", func(t *testing.T) {
		siteConfig := config.SiteConfig{Depth: 1}
		p := createPipelineForTarget(client, logger, cfg, siteConfig)

		report := model.NewOnionScanReport(testServer.onionAddress)
		err := p.Execute(ctx, report)
		if err != nil {
			t.Fatalf("pipeline.Execute() error = %v", err)
		}

		// Verify report has some data
		if report.HiddenService != testServer.onionAddress {
			t.Errorf("expected HiddenService %q, got %q", testServer.onionAddress, report.HiddenService)
		}
		t.Logf("Pipeline execution completed. WebDetected=%v, PagesCrawled=%d",
			report.WebDetected, len(report.Crawls))
	})
}

// TestIntegrationCompareCommand tests the compare command end-to-end.
func TestIntegrationCompareCommand(t *testing.T) {
	skipIfShort(t)
	skipIfNoTor(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Start test infrastructure
	testServer := startTestOnionServer(ctx, t)
	defer testServer.stop(t)

	// Create temp directory for database
	tmpDir := t.TempDir()
	dbDir := filepath.Join(tmpDir, "db")

	// First, populate database with some scans
	db, err := database.Open(dbDir, database.DefaultOptions())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}

	// Create two scan reports with different findings
	report1 := &model.OnionScanReport{
		HiddenService: testServer.onionAddress,
		DateScanned:   time.Now().Add(-1 * time.Hour),
		SimpleReport: &model.SimpleReport{
			MediumCount: 2,
			Findings: []model.Finding{
				{Type: "email_address", Value: "old@example.com", Severity: model.SeverityMedium, SeverityText: "Medium"},
				{Type: "bitcoin_address", Value: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Severity: model.SeverityMedium, SeverityText: "Medium"},
			},
		},
	}

	report2 := &model.OnionScanReport{
		HiddenService: testServer.onionAddress,
		DateScanned:   time.Now(),
		SimpleReport: &model.SimpleReport{
			MediumCount: 1,
			InfoCount:   1,
			Findings: []model.Finding{
				{Type: "email_address", Value: "old@example.com", Severity: model.SeverityMedium, SeverityText: "Medium"},
				{Type: "onion_link", Value: "newfound.onion", Severity: model.SeverityInfo, SeverityText: "Info"},
			},
		},
	}

	if err := db.SaveScanReport(ctx, report1); err != nil {
		t.Fatalf("failed to save report1: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := db.SaveScanReport(ctx, report2); err != nil {
		t.Fatalf("failed to save report2: %v", err)
	}
	db.Close()

	// Test listScannedServices
	t.Run("listScannedServices", func(t *testing.T) {
		db2, err := database.Open(dbDir, database.Options{CreateIfNotExists: false, EnableWAL: true})
		if err != nil {
			t.Fatalf("failed to reopen database: %v", err)
		}
		defer db2.Close()

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err = listScannedServices(ctx, db2)

		w.Close()
		os.Stdout = oldStdout

		if err != nil {
			t.Fatalf("listScannedServices() error = %v", err)
		}

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		r.Close()
		output := buf.String()

		if !strings.Contains(output, testServer.onionAddress) {
			t.Errorf("expected output to contain onion address, got: %s", output)
		}
	})

	// Test listScanHistory
	t.Run("listScanHistory", func(t *testing.T) {
		db2, err := database.Open(dbDir, database.Options{CreateIfNotExists: false, EnableWAL: true})
		if err != nil {
			t.Fatalf("failed to reopen database: %v", err)
		}
		defer db2.Close()

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err = listScanHistory(ctx, db2, testServer.onionAddress)

		w.Close()
		os.Stdout = oldStdout

		if err != nil {
			t.Fatalf("listScanHistory() error = %v", err)
		}

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		r.Close()
		output := buf.String()

		if !strings.Contains(output, "Scan history for") {
			t.Errorf("expected scan history header, got: %s", output)
		}
	})

	// Test runComparison with text output
	t.Run("runComparison text output", func(t *testing.T) {
		db2, err := database.Open(dbDir, database.Options{CreateIfNotExists: false, EnableWAL: true})
		if err != nil {
			t.Fatalf("failed to reopen database: %v", err)
		}
		defer db2.Close()

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err = runComparison(ctx, db2, testServer.onionAddress, 0, "", false, false)

		w.Close()
		os.Stdout = oldStdout

		if err != nil {
			t.Fatalf("runComparison() error = %v", err)
		}

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		r.Close()
		output := buf.String()

		if !strings.Contains(output, "Scan Comparison") {
			t.Errorf("expected comparison header, got: %s", output)
		}
	})

	// Test runComparison with markdown output
	t.Run("runComparison markdown output", func(t *testing.T) {
		db2, err := database.Open(dbDir, database.Options{CreateIfNotExists: false, EnableWAL: true})
		if err != nil {
			t.Fatalf("failed to reopen database: %v", err)
		}
		defer db2.Close()

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err = runComparison(ctx, db2, testServer.onionAddress, 0, "", false, true)

		w.Close()
		os.Stdout = oldStdout

		if err != nil {
			t.Fatalf("runComparison() with markdown error = %v", err)
		}

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		r.Close()
		output := buf.String()

		if !strings.Contains(output, "# Scan Comparison") {
			t.Errorf("expected markdown header, got: %s", output)
		}
	})
}

// TestIntegrationStartEmbeddedTor tests starting an embedded Tor daemon.
// This directly tests the startEmbeddedTor function.
func TestIntegrationStartEmbeddedTor(t *testing.T) {
	skipIfShort(t)
	skipIfNoTor(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cfg := config.NewConfig()
	cfg.TorStartupTimeout = 5 * time.Minute

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	t.Log("Starting embedded Tor daemon...")
	client, embeddedTor, err := startEmbeddedTor(ctx, cfg, logger)
	if err != nil {
		t.Fatalf("startEmbeddedTor() error = %v", err)
	}
	defer embeddedTor.Stop()

	if client == nil {
		t.Error("expected non-nil client")
	}
	if !embeddedTor.IsRunning() {
		t.Error("expected embedded Tor to be running")
	}

	t.Logf("Embedded Tor started: SOCKS=%s, Control=%s",
		embeddedTor.SocksAddr(), embeddedTor.ControlAddr())

	// Verify connection works
	status := client.CheckConnection(ctx)
	if status != tor.ProxyStatusOK {
		t.Errorf("expected ProxyStatusOK, got %v", status)
	}
}

// Example_integrationTest demonstrates how to run integration tests.
func Example_integrationTest() {
	// Run integration tests with:
	//   go test -v ./cmd/onionscan/... -run TestIntegration
	//
	// Skip integration tests with:
	//   go test -v -short ./cmd/onionscan/...
	//
	// Integration tests require:
	// - Real Tor daemon (started automatically via tornago)
	// - Network connectivity to Tor network
	// - 5-15 minutes per test

	fmt.Println("See TestIntegrationScanWithRealTor for a complete example")
	// Output: See TestIntegrationScanWithRealTor for a complete example
}
