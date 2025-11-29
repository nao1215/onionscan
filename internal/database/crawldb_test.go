package database

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nao1215/onionscan/internal/model"
)

// setupTestDB creates a temporary database for testing.
func setupTestDB(t *testing.T) (*CrawlDB, func()) {
	t.Helper()

	tmpDir := t.TempDir()

	db, err := Open(tmpDir, DefaultOptions())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}

	cleanup := func() {
		_ = db.Close()
	}

	return db, cleanup
}

// TestOpen tests database opening and creation.
func TestOpen(t *testing.T) {
	t.Parallel()

	t.Run("creates database in new directory", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()

		dbDir := filepath.Join(tmpDir, "newdir", "subdir")
		db, err := Open(dbDir, DefaultOptions())
		if err != nil {
			t.Fatalf("failed to open database: %v", err)
		}
		defer db.Close()

		// Check that database file exists
		dbPath := filepath.Join(dbDir, "onionscan.db")
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			t.Error("database file was not created")
		}
	})

	t.Run("CreateIfNotExists=true creates new database", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		dbDir := filepath.Join(tmpDir, "create-new")

		opts := Options{
			CreateIfNotExists: true,
			EnableWAL:         true,
		}

		db, err := Open(dbDir, opts)
		if err != nil {
			t.Fatalf("failed to open database with CreateIfNotExists=true: %v", err)
		}
		defer db.Close()

		// Verify database file was created
		dbPath := filepath.Join(dbDir, "onionscan.db")
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			t.Error("database file should have been created")
		}
	})

	t.Run("CreateIfNotExists=false returns error when database does not exist", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		dbDir := filepath.Join(tmpDir, "nonexistent-db")

		opts := Options{
			CreateIfNotExists: false,
			EnableWAL:         true,
		}

		_, err := Open(dbDir, opts)
		if err == nil {
			t.Fatal("expected error when CreateIfNotExists=false and database does not exist")
		}

		// Verify error message is informative
		expectedMsg := "database not found"
		if !contains(err.Error(), expectedMsg) {
			t.Errorf("expected error to contain %q, got %q", expectedMsg, err.Error())
		}

		// Verify database directory was NOT created
		if _, statErr := os.Stat(dbDir); !os.IsNotExist(statErr) {
			t.Error("database directory should not have been created when CreateIfNotExists=false")
		}
	})

	t.Run("CreateIfNotExists=false opens existing database", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		dbDir := filepath.Join(tmpDir, "existing-db")

		// First create the database
		createOpts := Options{
			CreateIfNotExists: true,
			EnableWAL:         true,
		}
		db1, err := Open(dbDir, createOpts)
		if err != nil {
			t.Fatalf("failed to create database: %v", err)
		}

		// Insert a test record to verify data persists
		ctx := context.Background()
		record := &CrawlRecord{
			URL:          "http://test.onion/page",
			OnionService: "test.onion",
			StatusCode:   200,
		}
		if _, err := db1.InsertCrawlRecord(ctx, record); err != nil {
			t.Fatalf("failed to insert record: %v", err)
		}
		db1.Close()

		// Now open with CreateIfNotExists=false
		openOpts := Options{
			CreateIfNotExists: false,
			EnableWAL:         true,
		}
		db2, err := Open(dbDir, openOpts)
		if err != nil {
			t.Fatalf("failed to open existing database with CreateIfNotExists=false: %v", err)
		}
		defer db2.Close()

		// Verify data persists
		retrieved, err := db2.GetCrawlRecord(ctx, record.URL, record.OnionService)
		if err != nil {
			t.Fatalf("failed to get record: %v", err)
		}
		if retrieved == nil {
			t.Error("expected record to exist in database")
		}
	})

	t.Run("CreateIfNotExists=false with directory but no db file", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		dbDir := filepath.Join(tmpDir, "empty-dir")

		// Create the directory but not the database file
		if err := os.MkdirAll(dbDir, 0750); err != nil {
			t.Fatalf("failed to create directory: %v", err)
		}

		opts := Options{
			CreateIfNotExists: false,
			EnableWAL:         true,
		}

		_, err := Open(dbDir, opts)
		if err == nil {
			t.Fatal("expected error when directory exists but database file does not")
		}
	})
}

// TestDefaultOptions tests the default options values.
func TestDefaultOptions(t *testing.T) {
	t.Parallel()

	opts := DefaultOptions()

	if !opts.CreateIfNotExists {
		t.Error("expected CreateIfNotExists to be true by default")
	}
	if !opts.EnableWAL {
		t.Error("expected EnableWAL to be true by default")
	}
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

// containsAt checks if s contains substr at any position.
func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestInsertAndGetCrawlRecord tests crawl record operations.
func TestInsertAndGetCrawlRecord(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("insert and retrieve record", func(t *testing.T) {
		record := &CrawlRecord{
			URL:          "http://example.onion/page",
			OnionService: "example.onion",
			StatusCode:   200,
			ContentType:  "text/html",
			Title:        "Test Page",
			Snapshot:     "This is test content",
			RawHash:      "abc123",
			Headers: map[string][]string{
				"Server": {"nginx"},
			},
		}

		id, err := db.InsertCrawlRecord(ctx, record)
		if err != nil {
			t.Fatalf("failed to insert record: %v", err)
		}
		if id == 0 {
			t.Error("expected non-zero ID")
		}

		// Retrieve the record
		retrieved, err := db.GetCrawlRecord(ctx, record.URL, record.OnionService)
		if err != nil {
			t.Fatalf("failed to get record: %v", err)
		}
		if retrieved == nil {
			t.Fatal("expected record, got nil")
		}

		if retrieved.Title != "Test Page" {
			t.Errorf("expected title 'Test Page', got %q", retrieved.Title)
		}
		if retrieved.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", retrieved.StatusCode)
		}
		if len(retrieved.Headers["Server"]) != 1 || retrieved.Headers["Server"][0] != "nginx" {
			t.Errorf("headers mismatch: %v", retrieved.Headers)
		}
	})

	t.Run("upsert updates existing record", func(t *testing.T) {
		record := &CrawlRecord{
			URL:          "http://example.onion/upsert",
			OnionService: "example.onion",
			StatusCode:   200,
			Title:        "Original Title",
		}

		_, err := db.InsertCrawlRecord(ctx, record)
		if err != nil {
			t.Fatalf("failed to insert: %v", err)
		}

		// Update with new title
		record.Title = "Updated Title"
		record.StatusCode = 404

		_, err = db.InsertCrawlRecord(ctx, record)
		if err != nil {
			t.Fatalf("failed to upsert: %v", err)
		}

		// Verify update
		retrieved, err := db.GetCrawlRecord(ctx, record.URL, record.OnionService)
		if err != nil {
			t.Fatalf("failed to get: %v", err)
		}
		if retrieved.Title != "Updated Title" {
			t.Errorf("expected 'Updated Title', got %q", retrieved.Title)
		}
		if retrieved.StatusCode != http.StatusNotFound {
			t.Errorf("expected status 404, got %d", retrieved.StatusCode)
		}
	})

	t.Run("returns nil for non-existent record", func(t *testing.T) {
		retrieved, err := db.GetCrawlRecord(ctx, "http://nonexistent.onion", "nonexistent.onion")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if retrieved != nil {
			t.Error("expected nil for non-existent record")
		}
	})
}

// TestHasRecentCrawl tests recent crawl checking.
func TestHasRecentCrawl(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Insert a record
	record := &CrawlRecord{
		URL:          "http://example.onion/recent",
		OnionService: "example.onion",
		StatusCode:   200,
	}
	_, err := db.InsertCrawlRecord(ctx, record)
	if err != nil {
		t.Fatalf("failed to insert: %v", err)
	}

	t.Run("returns true for recent crawl", func(t *testing.T) {
		hasRecent, err := db.HasRecentCrawl(ctx, record.URL, time.Hour)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !hasRecent {
			t.Error("expected true for recently inserted record")
		}
	})

	t.Run("returns false for non-existent URL", func(t *testing.T) {
		hasRecent, err := db.HasRecentCrawl(ctx, "http://nonexistent.onion", time.Hour)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hasRecent {
			t.Error("expected false for non-existent URL")
		}
	})
}

// TestRelationships tests relationship operations.
func TestRelationships(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("insert and query relationships", func(t *testing.T) {
		rel := &Relationship{
			FromOnion:  "source.onion",
			ToValue:    "test@example.com",
			Type:       "email",
			Identifier: "email_address",
			Confidence: 0.9,
		}

		err := db.InsertRelationship(ctx, rel)
		if err != nil {
			t.Fatalf("failed to insert: %v", err)
		}

		// Query by onion
		results, err := db.QueryRelationships(ctx, "source.onion", "")
		if err != nil {
			t.Fatalf("failed to query: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if results[0].ToValue != "test@example.com" {
			t.Errorf("expected email, got %q", results[0].ToValue)
		}
	})

	t.Run("query by type", func(t *testing.T) {
		// Insert multiple relationships
		rels := []*Relationship{
			{FromOnion: "test.onion", ToValue: "email1@example.com", Type: "email"},
			{FromOnion: "test.onion", ToValue: "email2@example.com", Type: "email"},
			{FromOnion: "test.onion", ToValue: "1BTC...", Type: "bitcoin"},
		}

		for _, rel := range rels {
			if err := db.InsertRelationship(ctx, rel); err != nil {
				t.Fatalf("failed to insert: %v", err)
			}
		}

		// Query only emails
		results, err := db.QueryRelationships(ctx, "test.onion", "email")
		if err != nil {
			t.Fatalf("failed to query: %v", err)
		}
		if len(results) != 2 {
			t.Errorf("expected 2 email results, got %d", len(results))
		}
	})
}

// TestScanReports tests scan report operations.
func TestScanReports(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("save and retrieve report", func(t *testing.T) {
		report := model.NewOnionScanReport("test.onion")
		report.WebDetected = true
		report.SSHDetected = true
		report.SimpleReport = model.NewSimpleReport(report)

		err := db.SaveScanReport(ctx, report)
		if err != nil {
			t.Fatalf("failed to save: %v", err)
		}

		// Retrieve
		retrieved, err := db.GetLatestScanReport(ctx, "test.onion")
		if err != nil {
			t.Fatalf("failed to get: %v", err)
		}
		if retrieved == nil {
			t.Fatal("expected report, got nil")
		}
		if !retrieved.WebDetected {
			t.Error("expected WebDetected to be true")
		}
	})

	t.Run("returns nil for non-existent service", func(t *testing.T) {
		retrieved, err := db.GetLatestScanReport(ctx, "nonexistent.onion")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if retrieved != nil {
			t.Error("expected nil for non-existent service")
		}
	})

	t.Run("list scanned services", func(t *testing.T) {
		// Save reports for multiple services
		for _, service := range []string{"service1.onion", "service2.onion"} {
			report := model.NewOnionScanReport(service)
			report.SimpleReport = model.NewSimpleReport(report)
			if err := db.SaveScanReport(ctx, report); err != nil {
				t.Fatalf("failed to save: %v", err)
			}
		}

		services, err := db.ListScannedServices(ctx)
		if err != nil {
			t.Fatalf("failed to list: %v", err)
		}

		// Should include test.onion from previous test plus the two new ones
		if len(services) < 2 {
			t.Errorf("expected at least 2 services, got %d", len(services))
		}
	})
}

// TestGetScanHistory tests retrieval of scan history for a service.
func TestGetScanHistory(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("returns empty list for non-existent service", func(t *testing.T) {
		history, err := db.GetScanHistory(ctx, "nonexistent.onion")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(history) != 0 {
			t.Errorf("expected empty history, got %d reports", len(history))
		}
	})

	t.Run("returns all scan reports for service in order", func(t *testing.T) {
		// Save multiple reports for same service
		for i := range 3 {
			report := model.NewOnionScanReport("history.onion")
			report.WebDetected = i%2 == 0
			report.SimpleReport = model.NewSimpleReport(report)
			if err := db.SaveScanReport(ctx, report); err != nil {
				t.Fatalf("failed to save report %d: %v", i, err)
			}
			// Small delay to ensure different timestamps
			time.Sleep(10 * time.Millisecond)
		}

		history, err := db.GetScanHistory(ctx, "history.onion")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(history) != 3 {
			t.Errorf("expected 3 reports, got %d", len(history))
		}

		// Verify all reports are for correct service
		for _, report := range history {
			if report.HiddenService != "history.onion" {
				t.Errorf("expected service 'history.onion', got %q", report.HiddenService)
			}
		}
	})
}

// TestGetScanHistoryWithMetadata tests retrieval of scan history metadata.
func TestGetScanHistoryWithMetadata(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("returns empty list for non-existent service", func(t *testing.T) {
		history, err := db.GetScanHistoryWithMetadata(ctx, "nonexistent.onion")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(history) != 0 {
			t.Errorf("expected empty history, got %d records", len(history))
		}
	})

	t.Run("returns metadata for all scans", func(t *testing.T) {
		// Save multiple reports with different risk counts
		for i := range 3 {
			report := model.NewOnionScanReport("metadata.onion")
			report.SimpleReport = &model.SimpleReport{
				CriticalCount: i,
				HighCount:     i + 1,
			}
			if err := db.SaveScanReport(ctx, report); err != nil {
				t.Fatalf("failed to save report %d: %v", i, err)
			}
			time.Sleep(10 * time.Millisecond)
		}

		history, err := db.GetScanHistoryWithMetadata(ctx, "metadata.onion")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(history) != 3 {
			t.Errorf("expected 3 records, got %d", len(history))
		}

		// Verify metadata fields are populated
		for _, meta := range history {
			if meta.ID == 0 {
				t.Error("expected non-zero ID")
			}
			if meta.OnionService != "metadata.onion" {
				t.Errorf("expected 'metadata.onion', got %q", meta.OnionService)
			}
			if meta.RiskSummary == nil {
				t.Error("expected non-nil RiskSummary")
			}
		}
	})
}

// TestGetScanReportByID tests retrieval of scan report by ID.
func TestGetScanReportByID(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("returns nil for non-existent ID", func(t *testing.T) {
		report, err := db.GetScanReportByID(ctx, 99999)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if report != nil {
			t.Error("expected nil for non-existent ID")
		}
	})

	t.Run("retrieves report by ID", func(t *testing.T) {
		// Save a report and get its ID
		original := model.NewOnionScanReport("byid.onion")
		original.WebDetected = true
		original.SimpleReport = model.NewSimpleReport(original)
		if err := db.SaveScanReport(ctx, original); err != nil {
			t.Fatalf("failed to save report: %v", err)
		}

		// Get the ID from metadata
		metadata, err := db.GetScanHistoryWithMetadata(ctx, "byid.onion")
		if err != nil {
			t.Fatalf("failed to get metadata: %v", err)
		}
		if len(metadata) == 0 {
			t.Fatal("expected at least one metadata record")
		}

		id := metadata[0].ID

		// Retrieve by ID
		retrieved, err := db.GetScanReportByID(ctx, id)
		if err != nil {
			t.Fatalf("failed to get report by ID: %v", err)
		}
		if retrieved == nil {
			t.Fatal("expected report, got nil")
		}
		if retrieved.HiddenService != "byid.onion" {
			t.Errorf("expected 'byid.onion', got %q", retrieved.HiddenService)
		}
		if !retrieved.WebDetected {
			t.Error("expected WebDetected to be true")
		}
	})
}
