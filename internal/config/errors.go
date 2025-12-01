package config

import "errors"

// Configuration validation errors.
// These errors are returned by Config.Validate() and provide specific
// information about what is wrong with the configuration.
//
// Design decision: We use package-level sentinel errors rather than
// creating new error instances in Validate(). This allows callers to use
// errors.Is() for programmatic error handling while still providing
// human-readable messages. Using errors.New() here rather than fmt.Errorf()
// because we don't need to include dynamic values in these messages.
var (
	// ErrNoTarget is returned when no target onion address or list file is specified.
	// This error occurs when neither --list nor a positional argument provides a target.
	ErrNoTarget = errors.New("no target specified: provide an onion address or use --list")

	// ErrInvalidTimeout is returned when the timeout is not positive.
	// A timeout of zero or negative would cause immediate connection failures.
	ErrInvalidTimeout = errors.New("invalid timeout: must be positive")

	// ErrInvalidBatchSize is returned when the batch size is not positive.
	// A batch size of zero would mean no concurrent scans, effectively stopping
	// the scanning process.
	ErrInvalidBatchSize = errors.New("invalid batch size: must be positive")

	// ErrConflictingReportFormats is returned when both --json and --markdown
	// are specified. Only one output format can be used at a time.
	ErrConflictingReportFormats = errors.New("conflicting report formats: --json and --markdown cannot be used together")

	// ErrInvalidCrawlDelay is returned when the crawl delay is negative.
	// A negative delay is invalid; use 0 for no delay between requests.
	ErrInvalidCrawlDelay = errors.New("invalid crawl delay: must be non-negative")

	// ErrInvalidMaxBodySize is returned when the max body size is negative.
	// A negative body size is invalid; use 0 to use the default limit.
	ErrInvalidMaxBodySize = errors.New("invalid max body size: must be non-negative")
)
