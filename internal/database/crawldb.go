package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // SQLite driver

	"github.com/nao1215/onionscan/internal/model"
)

// CrawlDB provides SQLite-based storage for crawl data and scan reports.
// It manages connection pooling and provides methods for CRUD operations.
//
// Design decision: We use a single database file per scan session rather
// than separate files per hidden service. This simplifies relationship
// queries and backup/restore operations.
type CrawlDB struct {
	// db is the underlying SQL database connection.
	db *sql.DB

	// dbPath is the path to the SQLite database file.
	dbPath string
}

// Options configures CrawlDB behavior.
type Options struct {
	// CreateIfNotExists creates the database file if it doesn't exist.
	CreateIfNotExists bool

	// EnableWAL enables Write-Ahead Logging for better concurrent performance.
	// This is recommended for most use cases.
	EnableWAL bool
}

// DefaultOptions returns the default database options.
func DefaultOptions() Options {
	return Options{
		CreateIfNotExists: true,
		EnableWAL:         true,
	}
}

// Open opens or creates a CrawlDB at the specified path.
// If CreateIfNotExists is true, the directory and database file are created.
// If CreateIfNotExists is false and the database doesn't exist, an error is returned.
func Open(dbDir string, opts Options) (*CrawlDB, error) {
	dbPath := filepath.Join(dbDir, "onionscan.db")

	// Check if we should create the database or require it to exist
	if !opts.CreateIfNotExists {
		// Check if database file exists
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("database not found at %s (use CreateIfNotExists option to create)", dbPath)
		} else if err != nil {
			return nil, fmt.Errorf("failed to check database path: %w", err)
		}
	} else {
		// Ensure directory exists
		if err := os.MkdirAll(dbDir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create database directory: %w", err)
		}
	}

	// Build connection string
	// We use modernc.org/sqlite which uses a different connection string format.
	// When CreateIfNotExists is false, we use mode=rw to prevent creating new files.
	// When CreateIfNotExists is true, we use mode=rwc to allow creation.
	var dsn string
	if opts.CreateIfNotExists {
		dsn = dbPath + "?mode=rwc"
	} else {
		dsn = dbPath + "?mode=rw"
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	// SQLite doesn't benefit from multiple connections for writes,
	// but multiple readers can improve performance
	db.SetMaxOpenConns(1) // SQLite only supports one writer
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)

	cdb := &CrawlDB{
		db:     db,
		dbPath: dbPath,
	}

	// Enable WAL mode if requested
	if opts.EnableWAL {
		if _, err := db.ExecContext(context.Background(), "PRAGMA journal_mode=WAL"); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
		}
	}

	// Create tables
	if err := cdb.createTables(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return cdb, nil
}

// Close closes the database connection.
func (cdb *CrawlDB) Close() error {
	return cdb.db.Close()
}

// createTables creates the database schema if it doesn't exist.
func (cdb *CrawlDB) createTables() error {
	schema := `
	-- Crawl records store individual page fetches
	CREATE TABLE IF NOT EXISTS crawls (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		url TEXT NOT NULL,
		onion_service TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		status_code INTEGER,
		content_type TEXT,
		title TEXT,
		snapshot TEXT,
		raw_hash TEXT,
		headers TEXT,
		UNIQUE(url, onion_service)
	);

	CREATE INDEX IF NOT EXISTS idx_crawls_url ON crawls(url);
	CREATE INDEX IF NOT EXISTS idx_crawls_onion ON crawls(onion_service);
	CREATE INDEX IF NOT EXISTS idx_crawls_timestamp ON crawls(timestamp);

	-- Relationships track connections between hidden services and identifiers
	CREATE TABLE IF NOT EXISTS relationships (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		from_onion TEXT NOT NULL,
		to_value TEXT NOT NULL,
		type TEXT NOT NULL,
		identifier TEXT,
		confidence REAL DEFAULT 1.0,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_rel_from ON relationships(from_onion);
	CREATE INDEX IF NOT EXISTS idx_rel_type ON relationships(type);
	CREATE INDEX IF NOT EXISTS idx_rel_identifier ON relationships(identifier);

	-- Scan reports store complete scan results as JSON
	CREATE TABLE IF NOT EXISTS scan_reports (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		onion_service TEXT NOT NULL,
		onion_version INTEGER DEFAULT 3,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		report_json TEXT NOT NULL,
		risk_summary TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_reports_onion ON scan_reports(onion_service);
	CREATE INDEX IF NOT EXISTS idx_reports_timestamp ON scan_reports(timestamp);
	`

	_, err := cdb.db.ExecContext(context.Background(), schema)
	return err
}

// CrawlRecord represents a stored crawl result.
type CrawlRecord struct {
	ID           int64
	URL          string
	OnionService string
	Timestamp    time.Time
	StatusCode   int
	ContentType  string
	Title        string
	Snapshot     string
	RawHash      string
	Headers      map[string][]string
}

// InsertCrawlRecord inserts or updates a crawl record.
// Uses UPSERT to handle duplicates (same URL + onion service).
func (cdb *CrawlDB) InsertCrawlRecord(ctx context.Context, record *CrawlRecord) (int64, error) {
	// Serialize headers to JSON
	headersJSON, err := json.Marshal(record.Headers)
	if err != nil {
		return 0, fmt.Errorf("failed to serialize headers: %w", err)
	}

	query := `
	INSERT INTO crawls (url, onion_service, status_code, content_type, title, snapshot, raw_hash, headers)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(url, onion_service) DO UPDATE SET
		status_code = excluded.status_code,
		content_type = excluded.content_type,
		title = excluded.title,
		snapshot = excluded.snapshot,
		raw_hash = excluded.raw_hash,
		headers = excluded.headers,
		timestamp = CURRENT_TIMESTAMP
	`

	result, err := cdb.db.ExecContext(ctx, query,
		record.URL,
		record.OnionService,
		record.StatusCode,
		record.ContentType,
		record.Title,
		record.Snapshot,
		record.RawHash,
		string(headersJSON),
	)
	if err != nil {
		return 0, fmt.Errorf("failed to insert crawl record: %w", err)
	}

	return result.LastInsertId()
}

// GetCrawlRecord retrieves a crawl record by URL and onion service.
func (cdb *CrawlDB) GetCrawlRecord(ctx context.Context, url, onionService string) (*CrawlRecord, error) {
	query := `
	SELECT id, url, onion_service, timestamp, status_code, content_type, title, snapshot, raw_hash, headers
	FROM crawls
	WHERE url = ? AND onion_service = ?
	`

	var record CrawlRecord
	var headersJSON string
	var timestamp string

	err := cdb.db.QueryRowContext(ctx, query, url, onionService).Scan(
		&record.ID,
		&record.URL,
		&record.OnionService,
		&timestamp,
		&record.StatusCode,
		&record.ContentType,
		&record.Title,
		&record.Snapshot,
		&record.RawHash,
		&headersJSON,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get crawl record: %w", err)
	}

	// Parse timestamp (SQLite may return different formats depending on version/configuration)
	record.Timestamp = parseTimestamp(timestamp)

	// Parse headers
	if headersJSON != "" {
		if err := json.Unmarshal([]byte(headersJSON), &record.Headers); err != nil {
			return nil, fmt.Errorf("failed to parse headers: %w", err)
		}
	}

	return &record, nil
}

// HasRecentCrawl checks if a URL was crawled within the specified duration.
func (cdb *CrawlDB) HasRecentCrawl(ctx context.Context, url string, duration time.Duration) (bool, error) {
	query := `
	SELECT COUNT(*) FROM crawls
	WHERE url = ? AND timestamp > datetime('now', ?)
	`

	// SQLite datetime modifier format
	modifier := fmt.Sprintf("-%d seconds", int(duration.Seconds()))

	var count int
	err := cdb.db.QueryRowContext(ctx, query, url, modifier).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check recent crawl: %w", err)
	}

	return count > 0, nil
}

// Relationship represents a connection between entities.
type Relationship struct {
	ID         int64
	FromOnion  string
	ToValue    string
	Type       string
	Identifier string
	Confidence float64
	Timestamp  time.Time
}

// InsertRelationship inserts a new relationship record.
func (cdb *CrawlDB) InsertRelationship(ctx context.Context, rel *Relationship) error {
	query := `
	INSERT INTO relationships (from_onion, to_value, type, identifier, confidence)
	VALUES (?, ?, ?, ?, ?)
	`

	_, err := cdb.db.ExecContext(ctx, query,
		rel.FromOnion,
		rel.ToValue,
		rel.Type,
		rel.Identifier,
		rel.Confidence,
	)
	if err != nil {
		return fmt.Errorf("failed to insert relationship: %w", err)
	}

	return nil
}

// QueryRelationships queries relationships with optional filters.
func (cdb *CrawlDB) QueryRelationships(ctx context.Context, fromOnion, relType string) ([]Relationship, error) {
	query := `
	SELECT id, from_onion, to_value, type, identifier, confidence, timestamp
	FROM relationships
	WHERE 1=1
	`
	args := make([]interface{}, 0)

	if fromOnion != "" {
		query += " AND from_onion = ?"
		args = append(args, fromOnion)
	}
	if relType != "" {
		query += " AND type = ?"
		args = append(args, relType)
	}

	query += " ORDER BY timestamp DESC"

	rows, err := cdb.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query relationships: %w", err)
	}
	defer rows.Close()

	var results []Relationship
	for rows.Next() {
		var rel Relationship
		var timestamp string

		err := rows.Scan(
			&rel.ID,
			&rel.FromOnion,
			&rel.ToValue,
			&rel.Type,
			&rel.Identifier,
			&rel.Confidence,
			&timestamp,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan relationship: %w", err)
		}

		rel.Timestamp = parseTimestamp(timestamp)
		results = append(results, rel)
	}

	return results, rows.Err()
}

// SaveScanReport saves a complete scan report as JSON.
func (cdb *CrawlDB) SaveScanReport(ctx context.Context, report *model.OnionScanReport) error {
	// Serialize report to JSON
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("failed to serialize report: %w", err)
	}

	// Create risk summary
	riskSummary := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}
	if report.SimpleReport != nil {
		riskSummary["critical"] = report.SimpleReport.CriticalCount
		riskSummary["high"] = report.SimpleReport.HighCount
		riskSummary["medium"] = report.SimpleReport.MediumCount
		riskSummary["low"] = report.SimpleReport.LowCount
		riskSummary["info"] = report.SimpleReport.InfoCount
	}
	riskJSON, _ := json.Marshal(riskSummary) //nolint:errcheck,errchkjson // riskSummary is a simple map; Marshal won't fail

	query := `
	INSERT INTO scan_reports (onion_service, onion_version, report_json, risk_summary)
	VALUES (?, ?, ?, ?)
	`

	_, err = cdb.db.ExecContext(ctx, query,
		report.HiddenService,
		report.OnionVersion,
		string(reportJSON),
		string(riskJSON),
	)
	if err != nil {
		return fmt.Errorf("failed to save scan report: %w", err)
	}

	return nil
}

// GetLatestScanReport retrieves the most recent scan report for a hidden service.
func (cdb *CrawlDB) GetLatestScanReport(ctx context.Context, onionService string) (*model.OnionScanReport, error) {
	query := `
	SELECT report_json FROM scan_reports
	WHERE onion_service = ?
	ORDER BY timestamp DESC
	LIMIT 1
	`

	var reportJSON string
	err := cdb.db.QueryRowContext(ctx, query, onionService).Scan(&reportJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get scan report: %w", err)
	}

	var report model.OnionScanReport
	if err := json.Unmarshal([]byte(reportJSON), &report); err != nil {
		return nil, fmt.Errorf("failed to parse report: %w", err)
	}

	return &report, nil
}

// ListScannedServices returns a list of all scanned hidden services.
func (cdb *CrawlDB) ListScannedServices(ctx context.Context) ([]string, error) {
	query := `
	SELECT DISTINCT onion_service FROM scan_reports
	ORDER BY onion_service
	`

	rows, err := cdb.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}
	defer rows.Close()

	var services []string
	for rows.Next() {
		var service string
		if err := rows.Scan(&service); err != nil {
			return nil, fmt.Errorf("failed to scan service: %w", err)
		}
		services = append(services, service)
	}

	return services, rows.Err()
}

// GetScanHistory retrieves all scan reports for a hidden service.
func (cdb *CrawlDB) GetScanHistory(ctx context.Context, onionService string) ([]*model.OnionScanReport, error) {
	query := `
	SELECT report_json FROM scan_reports
	WHERE onion_service = ?
	ORDER BY timestamp DESC
	`

	rows, err := cdb.db.QueryContext(ctx, query, onionService)
	if err != nil {
		return nil, fmt.Errorf("failed to get scan history: %w", err)
	}
	defer rows.Close()

	var reports []*model.OnionScanReport
	for rows.Next() {
		var reportJSON string
		if err := rows.Scan(&reportJSON); err != nil {
			return nil, fmt.Errorf("failed to scan report: %w", err)
		}

		var report model.OnionScanReport
		if err := json.Unmarshal([]byte(reportJSON), &report); err != nil {
			continue // Skip malformed reports
		}
		reports = append(reports, &report)
	}

	return reports, rows.Err()
}

// ScanReportMetadata contains summary information about a scan report.
// This is used for displaying scan history without loading the full report.
type ScanReportMetadata struct {
	// ID is the unique identifier of the scan report in the database.
	ID int64

	// OnionService is the scanned hidden service address.
	OnionService string

	// Timestamp is when the scan was performed.
	Timestamp time.Time

	// RiskSummary contains counts of findings by severity level.
	RiskSummary map[string]int
}

// GetScanHistoryWithMetadata retrieves scan report metadata for a hidden service.
// This is more efficient than GetScanHistory when only metadata is needed.
func (cdb *CrawlDB) GetScanHistoryWithMetadata(ctx context.Context, onionService string) ([]ScanReportMetadata, error) {
	query := `
	SELECT id, onion_service, timestamp, risk_summary
	FROM scan_reports
	WHERE onion_service = ?
	ORDER BY timestamp DESC
	`

	rows, err := cdb.db.QueryContext(ctx, query, onionService)
	if err != nil {
		return nil, fmt.Errorf("failed to get scan history: %w", err)
	}
	defer rows.Close()

	var results []ScanReportMetadata
	for rows.Next() {
		var meta ScanReportMetadata
		var timestamp string
		var riskJSON sql.NullString

		if err := rows.Scan(&meta.ID, &meta.OnionService, &timestamp, &riskJSON); err != nil {
			return nil, fmt.Errorf("failed to scan metadata: %w", err)
		}

		// Parse timestamp
		meta.Timestamp = parseTimestamp(timestamp)

		// Parse risk summary
		if riskJSON.Valid && riskJSON.String != "" {
			if err := json.Unmarshal([]byte(riskJSON.String), &meta.RiskSummary); err != nil {
				meta.RiskSummary = make(map[string]int)
			}
		} else {
			meta.RiskSummary = make(map[string]int)
		}

		results = append(results, meta)
	}

	return results, rows.Err()
}

// GetScanReportByID retrieves a scan report by its database ID.
func (cdb *CrawlDB) GetScanReportByID(ctx context.Context, id int64) (*model.OnionScanReport, error) {
	query := `
	SELECT report_json FROM scan_reports
	WHERE id = ?
	`

	var reportJSON string
	err := cdb.db.QueryRowContext(ctx, query, id).Scan(&reportJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get scan report: %w", err)
	}

	var report model.OnionScanReport
	if err := json.Unmarshal([]byte(reportJSON), &report); err != nil {
		return nil, fmt.Errorf("failed to parse report: %w", err)
	}

	return &report, nil
}

// timestampFormats contains the timestamp formats that SQLite may return.
// The order matters: more specific formats should come first.
var timestampFormats = []string{
	"2006-01-02 15:04:05",     // SQLite default datetime format
	"2006-01-02T15:04:05Z",    // ISO 8601 with Z suffix
	"2006-01-02T15:04:05",     // ISO 8601 without timezone
	time.RFC3339,              // Full RFC3339 format
	time.RFC3339Nano,          // RFC3339 with nanoseconds
	"2006-01-02 15:04:05.999", // SQLite with milliseconds
}

// parseTimestamp attempts to parse a timestamp string using multiple formats.
// SQLite may return timestamps in different formats depending on configuration.
// If parsing fails with all formats, returns zero time.
func parseTimestamp(s string) time.Time {
	for _, format := range timestampFormats {
		if t, err := time.Parse(format, s); err == nil {
			return t
		}
	}
	// Return zero time if no format matches
	// This is a fallback to avoid breaking functionality for edge cases
	return time.Time{}
}
