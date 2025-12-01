package config

import (
	"path/filepath"
	"time"

	"github.com/adrg/xdg"
)

// Default configuration values.
// These values are chosen based on typical Tor network characteristics
// and the original OnionScan defaults where applicable.
const (
	// DefaultTorProxyAddress is the standard Tor SOCKS5 proxy address.
	// Port 9050 is the default for the Tor daemon's SOCKS port.
	// We use 127.0.0.1 instead of localhost to avoid DNS resolution overhead
	// and potential issues with IPv6 resolution on some systems.
	DefaultTorProxyAddress = "127.0.0.1:9050"

	// DefaultTimeout is set to 120 seconds because Tor connections are inherently
	// slower than clearnet connections due to the multiple relay hops.
	// A shorter timeout would result in many false negatives for slower hidden services.
	DefaultTimeout = 120 * time.Second

	// DefaultCrawlDepth of 100 allows thorough exploration of most hidden services
	// while preventing infinite crawling. This value balances completeness with
	// reasonable scan times. Larger sites may need this increased via CLI flags.
	DefaultCrawlDepth = 100

	// DefaultBatchSize of 10 concurrent scans balances throughput with resource usage.
	// Higher values may overwhelm the local Tor daemon or trigger rate limiting.
	// Lower values are safer but slower for large scan lists.
	DefaultBatchSize = 10

	// DefaultMaxPages is the maximum number of pages to crawl per hidden service.
	// This prevents runaway crawling on large or infinitely-generating sites.
	// Users can override this via the --max-pages CLI flag.
	DefaultMaxPages = 100

	// AppName is the application name used for XDG directory paths.
	AppName = "onionscan"

	// DefaultCrawlDelay is the delay between requests during crawling.
	// This is a politeness setting to avoid overwhelming hidden services.
	// 1 second is conservative and respectful of server resources.
	// Can be adjusted via --crawl-delay CLI flag.
	DefaultCrawlDelay = 1 * time.Second

	// DefaultUserAgent identifies OnionScan in HTTP requests.
	// Using a descriptive User-Agent is good practice and allows operators
	// to identify scanner traffic in their logs.
	DefaultUserAgent = "OnionScan/2.0 (+https://github.com/nao1215/onionscan)"

	// DefaultMaxBodySize limits the maximum response body size to read.
	// 5MB is sufficient for most HTML pages while preventing memory exhaustion
	// from unexpectedly large responses.
	DefaultMaxBodySize = 5 * 1024 * 1024 // 5MB

	// DefaultTorStartupTimeout is the maximum time to wait for the embedded
	// Tor daemon to bootstrap. 3 minutes is typically sufficient for most
	// network conditions, but may need to be increased for slow connections.
	DefaultTorStartupTimeout = 3 * time.Minute
)

// Config holds all configuration options for OnionScan.
// This struct is designed to be populated from CLI flags and passed through
// the application via dependency injection rather than global state.
//
// Design decision: We use a single flat struct instead of nested structs
// (e.g., CrawlConfig, ReportConfig) for simplicity. The number of options
// is manageable, and nesting would add complexity without significant benefit.
// If the configuration grows significantly, consider refactoring into sub-structs.
type Config struct {
	// TorProxyAddress is the address of the Tor SOCKS5 proxy in "host:port" format.
	// This is required for all network operations as OnionScan only communicates
	// through Tor to maintain operational security.
	TorProxyAddress string

	// Timeout is the connection timeout for each HTTP/TCP request.
	// This applies to individual connections, not the overall scan duration.
	// Tor's latency means this should be generous (60-300 seconds typical).
	Timeout time.Duration

	// CrawlDepth is the maximum recursion depth for web crawling.
	// Depth 0 means only fetch the initial page.
	// Higher values find more content but take longer and use more resources.
	CrawlDepth int

	// MaxPages is the maximum number of pages to crawl per hidden service.
	// This prevents runaway crawling on large or infinitely-generating sites.
	// A value of 0 means use the default (DefaultMaxPages).
	MaxPages int

	// Verbose enables detailed log output using slog.LevelDebug.
	// When false, only warnings and errors are logged.
	Verbose bool

	// BatchSize is the number of concurrent scans when processing multiple targets.
	// Higher values increase throughput but may overwhelm system resources.
	// The Tor daemon may also have connection limits.
	BatchSize int

	// ConfigFilePath is the path to the configuration file.
	// If empty, the tool searches for .onionscan in the current directory
	// and then in the user's home directory.
	ConfigFilePath string

	// SiteConfigs holds site-specific configurations loaded from the config file.
	// This is populated by LoadConfigFile and used during scanning.
	SiteConfigs *File

	// JSONReport enables JSON report output instead of human-readable format.
	// When true, outputs detailed JSON with all collected data.
	// When false, outputs human-readable simple report (default).
	// Mutually exclusive with MarkdownReport.
	JSONReport bool

	// MarkdownReport enables Markdown report output instead of human-readable format.
	// When true, outputs GitHub Flavored Markdown with tables, alerts, and pie charts.
	// When false, outputs human-readable simple report (default).
	// Mutually exclusive with JSONReport.
	MarkdownReport bool

	// ReportFile is the output file path for the report.
	// When set, the report is written to this file instead of stdout.
	// Directories are created automatically if they don't exist.
	ReportFile string

	// Targets is the list of onion addresses to scan.
	// Must contain at least one valid v3 onion address (56 characters + ".onion").
	Targets []string

	// UseExternalTor disables the embedded Tor daemon and uses an external proxy.
	// When false (default), OnionScan automatically starts an embedded Tor daemon.
	// When true, OnionScan expects an external Tor service at TorProxyAddress.
	//
	// Note: The embedded Tor daemon takes 1-3 minutes to bootstrap and connect
	// to the Tor network on first start.
	UseExternalTor bool

	// TorStartupTimeout is the maximum time to wait for the embedded Tor daemon
	// to start and bootstrap. Only used when UseExternalTor is false.
	TorStartupTimeout time.Duration

	// DBDir is the directory path for storing the SQLite database.
	// When set, scan results are saved to the database for historical comparison.
	// When empty, scan results are not persisted.
	// Defaults to XDG data directory (~/.local/share/onionscan on Linux).
	DBDir string

	// SaveToDB indicates whether to save scan results to the database.
	// This is automatically set to true when DBDir is configured.
	SaveToDB bool

	// CrawlDelay is the delay between HTTP requests during crawling.
	// This is a "politeness" setting to avoid overwhelming hidden services.
	// Lower values may cause rate limiting or service disruption.
	// Minimum recommended: 500ms for aggressive scanning, 1s for normal use.
	CrawlDelay time.Duration

	// UserAgent is the User-Agent header sent with HTTP requests.
	// A descriptive User-Agent helps service operators identify scanner traffic.
	// Can be customized for stealth scanning, but consider ethical implications.
	UserAgent string

	// MaxBodySize is the maximum response body size in bytes to read.
	// Responses larger than this are truncated to prevent memory exhaustion.
	// Set to 0 to use the default (5MB).
	MaxBodySize int64
}

// NewConfig creates a new Config with default values.
// All fields are set to safe, sensible defaults that work for most use cases.
// Users can override specific values after creation.
//
// Design decision: We use a constructor function instead of relying on
// zero values because many defaults are non-zero (e.g., timeout, port numbers).
// This also serves as documentation of what the defaults are.
func NewConfig() *Config {
	return &Config{
		TorProxyAddress:   DefaultTorProxyAddress,
		Timeout:           DefaultTimeout,
		CrawlDepth:        DefaultCrawlDepth,
		MaxPages:          DefaultMaxPages,
		BatchSize:         DefaultBatchSize,
		TorStartupTimeout: DefaultTorStartupTimeout,
		CrawlDelay:        DefaultCrawlDelay,
		UserAgent:         DefaultUserAgent,
		MaxBodySize:       DefaultMaxBodySize,
	}
}

// XDGDataDir returns the XDG data directory for OnionScan.
// This follows the XDG Base Directory Specification.
// On Linux: ~/.local/share/onionscan
// On macOS: ~/Library/Application Support/onionscan
// On Windows: %LOCALAPPDATA%\onionscan
func XDGDataDir() string {
	return filepath.Join(xdg.DataHome, AppName)
}

// XDGConfigDir returns the XDG config directory for OnionScan.
// This follows the XDG Base Directory Specification.
// On Linux: ~/.config/onionscan
// On macOS: ~/Library/Application Support/onionscan
// On Windows: %APPDATA%\onionscan
func XDGConfigDir() string {
	return filepath.Join(xdg.ConfigHome, AppName)
}

// XDGCacheDir returns the XDG cache directory for OnionScan.
// This follows the XDG Base Directory Specification.
// On Linux: ~/.cache/onionscan
// On macOS: ~/Library/Caches/onionscan
// On Windows: %LOCALAPPDATA%\onionscan\cache
func XDGCacheDir() string {
	return filepath.Join(xdg.CacheHome, AppName)
}

// Validate checks if the configuration is valid.
// It returns a specific error describing what is invalid.
//
// Design decision: We validate at the config level rather than at each
// point of use to fail fast and provide clear error messages upfront.
// This is called once after CLI parsing, before any scanning begins.
//
// We chose to return the first error found rather than collecting all errors
// because fixing one error often makes others irrelevant.
func (c *Config) Validate() error {
	// We must have at least one target to scan
	if len(c.Targets) == 0 {
		return ErrNoTarget
	}

	// Timeout must be positive; zero timeout would cause immediate failures
	if c.Timeout <= 0 {
		return ErrInvalidTimeout
	}

	// BatchSize must be positive; zero would mean no scanning
	if c.BatchSize <= 0 {
		return ErrInvalidBatchSize
	}

	// JSONReport and MarkdownReport are mutually exclusive
	if c.JSONReport && c.MarkdownReport {
		return ErrConflictingReportFormats
	}

	// CrawlDelay must be non-negative
	if c.CrawlDelay < 0 {
		return ErrInvalidCrawlDelay
	}

	// MaxBodySize must be positive if set
	if c.MaxBodySize < 0 {
		return ErrInvalidMaxBodySize
	}

	return nil
}
