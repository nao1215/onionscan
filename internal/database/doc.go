// Package database provides SQLite-based storage for OnionScan.
//
// This package implements the CrawlDB, which stores:
//   - Crawled page records with content and metadata
//   - Relationships between hidden services
//   - Scan reports for historical analysis
//
// Design decision: We use SQLite (via modernc.org/sqlite) instead of other
// databases because:
// 1. No external dependencies - the database is a single file
// 2. CGO-free implementation allows easy cross-compilation
// 3. Sufficient performance for our use case
// 4. WAL mode provides good concurrent read performance
//
// The original OnionScan used TiedotDB, which is no longer maintained.
// SQLite provides a more reliable and widely-supported alternative.
package database
