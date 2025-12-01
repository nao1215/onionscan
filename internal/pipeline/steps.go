package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/nao1215/onionscan/internal/config"
	"github.com/nao1215/onionscan/internal/crawler"
	"github.com/nao1215/onionscan/internal/deanon"
	"github.com/nao1215/onionscan/internal/model"
	"github.com/nao1215/onionscan/internal/protocol"
	"github.com/nao1215/onionscan/internal/tor"
)

// HTTPScanStep performs HTTP protocol scanning on the target service.
// This step probes HTTP/HTTPS ports and collects server information,
// headers, and initial response data.
//
// Design decision: HTTP scanning is a separate step because:
// 1. It's the foundation for web-based services
// 2. Results inform subsequent steps (crawler needs HTTP to work)
// 3. Can be skipped if only checking other protocols
type HTTPScanStep struct {
	// client is the HTTP client configured with Tor proxy.
	client *http.Client

	// maxBodySize limits the response body size.
	maxBodySize int64

	// logger for structured logging.
	logger *slog.Logger
}

// HTTPScanStepOption configures an HTTPScanStep.
type HTTPScanStepOption func(*HTTPScanStep)

// WithHTTPMaxBodySize sets the maximum body size for HTTP responses.
func WithHTTPMaxBodySize(size int64) HTTPScanStepOption {
	return func(s *HTTPScanStep) {
		s.maxBodySize = size
	}
}

// WithHTTPLogger sets a custom logger for the HTTP scan step.
func WithHTTPLogger(logger *slog.Logger) HTTPScanStepOption {
	return func(s *HTTPScanStep) {
		s.logger = logger
	}
}

// NewHTTPScanStep creates a new HTTP scanning step.
// The client must be pre-configured with Tor SOCKS5 proxy.
func NewHTTPScanStep(client *http.Client, opts ...HTTPScanStepOption) *HTTPScanStep {
	s := &HTTPScanStep{
		client:      client,
		maxBodySize: config.DefaultMaxBodySize,
		logger:      slog.Default(),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Name returns the step name.
func (s *HTTPScanStep) Name() string {
	return "http_scan"
}

// Do executes the HTTP scan step.
func (s *HTTPScanStep) Do(ctx context.Context, report *model.OnionScanReport) error {
	scanner := protocol.NewHTTPScanner(
		s.client,
		protocol.WithMaxBodySize(s.maxBodySize),
	)

	// Try HTTP first
	httpURL := "http://" + report.HiddenService
	result, err := scanner.Scan(ctx, httpURL)
	if err != nil {
		s.logger.Debug("HTTP scan failed", "url", httpURL, "error", err)
	} else if result.Detected {
		report.WebDetected = true
		report.ServerVersion = result.Banner
		if result.Headers != nil {
			report.AnonymityReport.ServerVersion = result.Headers.Get("Server")
			report.AnonymityReport.XPoweredBy = result.Headers.Get("X-Powered-By")
		}

		// Add protocol findings
		for _, f := range result.Findings {
			report.AddFinding(model.Finding{
				Type:         f.Type,
				Title:        f.Title,
				Description:  f.Description,
				Severity:     f.Severity,
				SeverityText: f.Severity.String(),
				Value:        f.Value,
				Location:     httpURL,
			})
		}
	}

	// Try HTTPS
	httpsURL := "https://" + report.HiddenService
	httpsResult, err := scanner.Scan(ctx, httpsURL)
	if err != nil {
		s.logger.Debug("HTTPS scan failed", "url", httpsURL, "error", err)
	} else if httpsResult.Detected {
		report.WebDetected = true
		report.TLSDetected = true

		// TLS certificate analysis
		if httpsResult.Certificate != nil {
			report.TLSCertificate = &model.CertInfo{
				Subject:    httpsResult.Certificate.Subject,
				Issuer:     httpsResult.Certificate.Issuer,
				NotBefore:  httpsResult.Certificate.NotBefore,
				NotAfter:   httpsResult.Certificate.NotAfter,
				CommonName: httpsResult.Certificate.CommonName,
				SANs:       httpsResult.Certificate.SANs,
			}
		}

		// Add HTTPS-specific findings
		for _, f := range httpsResult.Findings {
			report.AddFinding(model.Finding{
				Type:         f.Type,
				Title:        f.Title,
				Description:  f.Description,
				Severity:     f.Severity,
				SeverityText: f.Severity.String(),
				Value:        f.Value,
				Location:     httpsURL,
			})
		}
	}

	return nil
}

// CrawlStep performs web crawling on the target service.
// This step discovers pages, extracts content, and builds a sitemap.
//
// Design decision: Crawling is separate from HTTP scanning because:
// 1. It has different configuration (depth, limits, delay)
// 2. It produces different data (pages vs protocol info)
// 3. Can be disabled for quick scans
type CrawlStep struct {
	// client is the HTTP client configured with Tor proxy.
	client *http.Client

	// maxDepth limits crawl recursion.
	maxDepth int

	// maxPages limits total pages to crawl.
	maxPages int

	// delay between requests for politeness.
	delay time.Duration

	// userAgent is the User-Agent header to send with requests.
	// A descriptive User-Agent helps service operators identify scanner traffic.
	userAgent string

	// maxBodySize limits the size of response bodies to read.
	// This prevents memory exhaustion from unexpectedly large responses.
	maxBodySize int64

	// ignorePatterns are URL path patterns to skip during crawling.
	ignorePatterns []string

	// followPatterns are URL path patterns to follow during crawling.
	followPatterns []string

	// logger for structured logging.
	logger *slog.Logger
}

// CrawlStepOption configures a CrawlStep.
type CrawlStepOption func(*CrawlStep)

// WithCrawlMaxDepth sets the maximum crawl depth.
func WithCrawlMaxDepth(depth int) CrawlStepOption {
	return func(s *CrawlStep) {
		s.maxDepth = depth
	}
}

// WithCrawlMaxPages sets the maximum pages to crawl.
func WithCrawlMaxPages(maxPages int) CrawlStepOption {
	return func(s *CrawlStep) {
		s.maxPages = maxPages
	}
}

// WithCrawlDelay sets the delay between requests.
func WithCrawlDelay(d time.Duration) CrawlStepOption {
	return func(s *CrawlStep) {
		s.delay = d
	}
}

// WithCrawlLogger sets a custom logger for the crawl step.
func WithCrawlLogger(logger *slog.Logger) CrawlStepOption {
	return func(s *CrawlStep) {
		s.logger = logger
	}
}

// WithCrawlIgnorePatterns sets URL path patterns to skip during crawling.
func WithCrawlIgnorePatterns(patterns []string) CrawlStepOption {
	return func(s *CrawlStep) {
		s.ignorePatterns = patterns
	}
}

// WithCrawlFollowPatterns sets URL path patterns to follow during crawling.
func WithCrawlFollowPatterns(patterns []string) CrawlStepOption {
	return func(s *CrawlStep) {
		s.followPatterns = patterns
	}
}

// WithCrawlUserAgent sets the User-Agent header for HTTP requests.
// A descriptive User-Agent helps service operators identify scanner traffic.
func WithCrawlUserAgent(userAgent string) CrawlStepOption {
	return func(s *CrawlStep) {
		s.userAgent = userAgent
	}
}

// WithCrawlMaxBodySize sets the maximum response body size in bytes.
// Responses larger than this are truncated to prevent memory exhaustion.
func WithCrawlMaxBodySize(maxBodySize int64) CrawlStepOption {
	return func(s *CrawlStep) {
		s.maxBodySize = maxBodySize
	}
}

// NewCrawlStep creates a new crawling step.
// The client must be pre-configured with Tor SOCKS5 proxy.
//
// Default politeness settings are conservative to be respectful of hidden services:
//   - delay: 1 second between requests (config.DefaultCrawlDelay)
//   - userAgent: identifies OnionScan (config.DefaultUserAgent)
//   - maxBodySize: 5MB to prevent memory exhaustion (config.DefaultMaxBodySize)
func NewCrawlStep(client *http.Client, opts ...CrawlStepOption) *CrawlStep {
	s := &CrawlStep{
		client:      client,
		maxDepth:    5,
		maxPages:    config.DefaultMaxPages,
		delay:       config.DefaultCrawlDelay,
		userAgent:   config.DefaultUserAgent,
		maxBodySize: config.DefaultMaxBodySize,
		logger:      slog.Default(),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Name returns the step name.
func (s *CrawlStep) Name() string {
	return "crawl"
}

// Do executes the crawl step.
func (s *CrawlStep) Do(ctx context.Context, report *model.OnionScanReport) error {
	// Only crawl if HTTP was detected
	if !report.WebDetected {
		s.logger.Debug("skipping crawl, no web service detected")
		return nil
	}

	// Build spider options including politeness settings
	spiderOpts := []crawler.SpiderOption{
		crawler.WithMaxDepth(s.maxDepth),
		crawler.WithMaxPages(s.maxPages),
		crawler.WithDelay(s.delay),
		crawler.WithSpiderUserAgent(s.userAgent),
		crawler.WithSpiderMaxBodySize(s.maxBodySize),
	}

	// Add pattern filtering if configured
	if len(s.ignorePatterns) > 0 {
		spiderOpts = append(spiderOpts, crawler.WithIgnorePatterns(s.ignorePatterns))
	}
	if len(s.followPatterns) > 0 {
		spiderOpts = append(spiderOpts, crawler.WithFollowPatterns(s.followPatterns))
	}

	spider := crawler.NewSpider(s.client, spiderOpts...)

	startURL := "http://" + report.HiddenService
	pages, err := spider.Crawl(ctx, startURL)
	if err != nil {
		// Non-fatal: we may have partial results
		s.logger.Warn("crawl completed with error", "error", err)
	}

	// Store crawled pages in report
	report.CrawledPages = pages
	for _, page := range pages {
		report.AddPage(page.URL, page)
	}

	// Calculate crawl stats
	stats := spider.Stats()
	s.logger.Info("crawl completed",
		"pages_visited", stats.PagesVisited,
		"urls_queued", stats.URLsQueued,
	)

	return nil
}

// DeanonStep performs deanonymization analysis on collected data.
// This step analyzes pages for identity leaks, analytics tracking,
// cryptocurrency addresses, and other deanonymization vectors.
//
// Design decision: Deanon analysis is a separate step because:
// 1. It operates on accumulated data from previous steps
// 2. It has its own configuration (which analyzers to run)
// 3. Results are the primary security findings
type DeanonStep struct {
	// analyzer is the main analyzer coordinator.
	analyzer *deanon.Analyzer

	// logger for structured logging.
	logger *slog.Logger
}

// DeanonStepOption configures a DeanonStep.
type DeanonStepOption func(*DeanonStep)

// WithDeanonLogger sets a custom logger for the deanon step.
func WithDeanonLogger(logger *slog.Logger) DeanonStepOption {
	return func(s *DeanonStep) {
		s.logger = logger
	}
}

// WithDeanonHTTPClient injects an HTTP client into analyzers that need it (EXIF/PDF).
func WithDeanonHTTPClient(client *http.Client) DeanonStepOption {
	return func(s *DeanonStep) {
		s.analyzer.SetHTTPClient(client)
	}
}

// NewDeanonStep creates a new deanonymization analysis step.
func NewDeanonStep(opts ...DeanonStepOption) *DeanonStep {
	s := &DeanonStep{
		analyzer: deanon.NewAnalyzer(),
		logger:   slog.Default(),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Name returns the step name.
func (s *DeanonStep) Name() string {
	return "deanon"
}

// Do executes the deanonymization analysis step.
func (s *DeanonStep) Do(ctx context.Context, report *model.OnionScanReport) error {
	// Skip if no pages were crawled
	if len(report.CrawledPages) == 0 {
		s.logger.Debug("skipping deanon analysis, no pages crawled")
		return nil
	}

	// Prepare analysis data
	data := &deanon.AnalysisData{
		Report:          report,
		Pages:           report.CrawledPages,
		ProtocolResults: make(map[string]*protocol.ScanResult),
		HiddenService:   report.HiddenService,
	}

	// Run all analyzers
	findings, err := s.analyzer.Analyze(ctx, data)
	if err != nil {
		// Non-fatal: return partial results
		s.logger.Warn("deanon analysis completed with error", "error", err)
	}

	// Add findings to report
	for _, f := range findings {
		report.AddFinding(f)
	}

	s.logger.Info("deanon analysis completed",
		"findings_count", len(findings),
	)

	return nil
}

// ProtocolScanStep scans for non-HTTP services on the target.
// This step checks for SSH, FTP, SMTP, databases, and other protocols.
//
// Design decision: Protocol scanning is separate because:
// 1. Different protocols have different timeouts and methods
// 2. Results feed into technical fingerprinting
// 3. Can be selectively enabled/disabled
type ProtocolScanStep struct {
	// client is the Tor client for creating connections.
	client *tor.Client

	// protocols lists which protocols to scan.
	protocols []string

	// logger for structured logging.
	logger *slog.Logger
}

// ProtocolScanStepOption configures a ProtocolScanStep.
type ProtocolScanStepOption func(*ProtocolScanStep)

// WithProtocols sets which protocols to scan.
// Default is all supported protocols.
func WithProtocols(protocols []string) ProtocolScanStepOption {
	return func(s *ProtocolScanStep) {
		s.protocols = protocols
	}
}

// WithProtocolLogger sets a custom logger for the protocol scan step.
func WithProtocolLogger(logger *slog.Logger) ProtocolScanStepOption {
	return func(s *ProtocolScanStep) {
		s.logger = logger
	}
}

// NewProtocolScanStep creates a new protocol scanning step.
func NewProtocolScanStep(client *tor.Client, opts ...ProtocolScanStepOption) *ProtocolScanStep {
	s := &ProtocolScanStep{
		client: client,
		protocols: []string{
			"ssh", "ftp", "smtp",
			"mongodb", "redis", "postgresql", "mysql",
		},
		logger: slog.Default(),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Name returns the step name.
func (s *ProtocolScanStep) Name() string {
	return "protocol_scan"
}

// Do executes the protocol scan step.
func (s *ProtocolScanStep) Do(ctx context.Context, report *model.OnionScanReport) error {
	// Protocol scanners map
	type protocolInfo struct {
		port    int
		scanner protocol.Scanner
	}

	// Create scanners for each protocol
	conn := s.client.Dialer()

	scanners := map[string]protocolInfo{
		"ssh":        {22, protocol.NewSSHScanner(conn)},
		"ftp":        {21, protocol.NewFTPScanner(conn)},
		"smtp":       {25, protocol.NewSMTPScanner(conn)},
		"mongodb":    {27017, protocol.NewMongoDBScanner(conn)},
		"redis":      {6379, protocol.NewRedisScanner(conn)},
		"postgresql": {5432, protocol.NewPostgreSQLScanner(conn)},
		"mysql":      {3306, protocol.NewMySQLScanner(conn)},
	}

	// Scan each protocol
	for _, proto := range s.protocols {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		info, ok := scanners[proto]
		if !ok {
			s.logger.Warn("unknown protocol", "protocol", proto)
			continue
		}

		target := fmt.Sprintf("%s:%d", report.HiddenService, info.port)
		result, err := info.scanner.Scan(ctx, target)
		if err != nil {
			s.logger.Debug("protocol scan failed",
				"protocol", proto,
				"error", err,
			)
			continue
		}

		if result.Detected {
			s.logger.Info("service detected",
				"protocol", proto,
				"port", info.port,
				"banner", result.Banner,
			)

			// Store protocol results
			switch proto {
			case "ssh":
				report.SSHDetected = true
				report.SSHBanner = result.Banner
			case "ftp":
				report.FTPDetected = true
				report.FTPBanner = result.Banner
			case "smtp":
				report.SMTPDetected = true
				report.SMTPBanner = result.Banner
			case "mongodb":
				report.MongoDBDetected = true
			case "redis":
				report.RedisDetected = true
			case "postgresql":
				report.PostgreSQLDetected = true
			case "mysql":
				report.MySQLDetected = true
			}

			// Add protocol findings
			for _, f := range result.Findings {
				report.AddFinding(model.Finding{
					Type:         f.Type,
					Title:        f.Title,
					Description:  f.Description,
					Severity:     f.Severity,
					SeverityText: f.Severity.String(),
					Value:        f.Value,
					Location:     target,
				})
			}
		}
	}

	return nil
}

// DefaultPipelineConfig holds configuration for the default pipeline.
type DefaultPipelineConfig struct {
	// CrawlDepth is the maximum depth for web crawling.
	CrawlDepth int

	// CrawlMaxPages is the maximum number of pages to crawl.
	CrawlMaxPages int

	// Cookie is the cookie string to send with HTTP requests.
	Cookie string

	// Headers are additional HTTP headers to send with requests.
	Headers map[string]string

	// IgnorePatterns are URL path patterns to skip during crawling.
	IgnorePatterns []string

	// FollowPatterns are URL path patterns to follow during crawling.
	FollowPatterns []string

	// CrawlDelay is the delay between HTTP requests during crawling.
	// This is a "politeness" setting to avoid overwhelming hidden services.
	CrawlDelay time.Duration

	// UserAgent is the User-Agent header sent with HTTP requests.
	// A descriptive User-Agent helps service operators identify scanner traffic.
	UserAgent string

	// MaxBodySize is the maximum response body size in bytes to read.
	// Responses larger than this are truncated to prevent memory exhaustion.
	MaxBodySize int64
}

// DefaultPipelineOption configures a DefaultPipelineConfig.
type DefaultPipelineOption func(*DefaultPipelineConfig)

// WithPipelineCrawlDepth sets the crawl depth for the pipeline.
func WithPipelineCrawlDepth(depth int) DefaultPipelineOption {
	return func(c *DefaultPipelineConfig) {
		c.CrawlDepth = depth
	}
}

// WithPipelineCrawlMaxPages sets the maximum pages to crawl.
func WithPipelineCrawlMaxPages(maxPages int) DefaultPipelineOption {
	return func(c *DefaultPipelineConfig) {
		c.CrawlMaxPages = maxPages
	}
}

// WithPipelineCookie sets the cookie for HTTP requests.
func WithPipelineCookie(cookie string) DefaultPipelineOption {
	return func(c *DefaultPipelineConfig) {
		c.Cookie = cookie
	}
}

// WithPipelineHeaders sets additional HTTP headers.
func WithPipelineHeaders(headers map[string]string) DefaultPipelineOption {
	return func(c *DefaultPipelineConfig) {
		c.Headers = headers
	}
}

// WithPipelineIgnorePatterns sets URL patterns to skip during crawling.
func WithPipelineIgnorePatterns(patterns []string) DefaultPipelineOption {
	return func(c *DefaultPipelineConfig) {
		c.IgnorePatterns = patterns
	}
}

// WithPipelineFollowPatterns sets URL patterns to follow during crawling.
func WithPipelineFollowPatterns(patterns []string) DefaultPipelineOption {
	return func(c *DefaultPipelineConfig) {
		c.FollowPatterns = patterns
	}
}

// WithPipelineCrawlDelay sets the delay between HTTP requests during crawling.
// This is a "politeness" setting to avoid overwhelming hidden services.
// A minimum of 500ms is recommended; 1s is the default for respectful scanning.
func WithPipelineCrawlDelay(delay time.Duration) DefaultPipelineOption {
	return func(c *DefaultPipelineConfig) {
		c.CrawlDelay = delay
	}
}

// WithPipelineUserAgent sets the User-Agent header for HTTP requests.
// A descriptive User-Agent helps service operators identify scanner traffic.
func WithPipelineUserAgent(userAgent string) DefaultPipelineOption {
	return func(c *DefaultPipelineConfig) {
		c.UserAgent = userAgent
	}
}

// WithPipelineMaxBodySize sets the maximum response body size in bytes.
// Responses larger than this are truncated to prevent memory exhaustion.
func WithPipelineMaxBodySize(maxBodySize int64) DefaultPipelineOption {
	return func(c *DefaultPipelineConfig) {
		c.MaxBodySize = maxBodySize
	}
}

// DefaultPipeline creates a pipeline with all default steps configured.
// This is the standard pipeline for comprehensive onion service scanning.
//
// Design decision: We provide a default pipeline because:
// 1. Most users want all checks
// 2. Reduces boilerplate in CLI
// 3. Ensures consistent ordering
//
// The first variadic parameter accepts pipeline options (WithLogger, etc).
// The second accepts pipeline config options (WithPipelineCrawlDepth, etc).
//
// Politeness settings (CrawlDelay, UserAgent, MaxBodySize) are important for
// being respectful of hidden services. See CLAUDE.md for recommended values.
func DefaultPipeline(client *tor.Client, pipelineOpts []Option, configOpts ...DefaultPipelineOption) *Pipeline {
	p := New(pipelineOpts...)

	// Apply default config with conservative politeness settings
	cfg := &DefaultPipelineConfig{
		CrawlDepth:    5,
		CrawlMaxPages: config.DefaultMaxPages,
		CrawlDelay:    config.DefaultCrawlDelay,
		UserAgent:     config.DefaultUserAgent,
		MaxBodySize:   config.DefaultMaxBodySize,
	}
	for _, opt := range configOpts {
		opt(cfg)
	}

	// Create HTTP client with optional custom headers/cookie
	httpClient := client.HTTPClient()
	if cfg.Cookie != "" || len(cfg.Headers) > 0 {
		httpClient = client.HTTPClientWithConfig(cfg.Cookie, cfg.Headers)
	}

	// Build crawl step options including politeness settings
	crawlOpts := []CrawlStepOption{
		WithCrawlMaxDepth(cfg.CrawlDepth),
		WithCrawlMaxPages(cfg.CrawlMaxPages),
		WithCrawlDelay(cfg.CrawlDelay),
		WithCrawlUserAgent(cfg.UserAgent),
		WithCrawlMaxBodySize(cfg.MaxBodySize),
	}

	// Add pattern filtering options if configured
	if len(cfg.IgnorePatterns) > 0 {
		crawlOpts = append(crawlOpts, WithCrawlIgnorePatterns(cfg.IgnorePatterns))
	}
	if len(cfg.FollowPatterns) > 0 {
		crawlOpts = append(crawlOpts, WithCrawlFollowPatterns(cfg.FollowPatterns))
	}

	// Build HTTP scan step options
	httpOpts := []HTTPScanStepOption{
		WithHTTPMaxBodySize(cfg.MaxBodySize),
	}

	// Add steps in logical order
	p.AddSteps(
		NewHTTPScanStep(httpClient, httpOpts...),
		NewProtocolScanStep(client),
		NewCrawlStep(httpClient, crawlOpts...),
		NewDeanonStep(
			WithDeanonHTTPClient(httpClient),
		),
	)

	return p
}
