package crawler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nao1215/onionscan/internal/model"
)

// Spider crawls web pages on onion services.
// It manages a queue of URLs to visit and respects depth and rate limits.
//
// Design decision: We call it "Spider" rather than "Crawler" because:
//  1. "Spider" is the traditional term for web crawlers
//  2. Distinguishes the component from the package name
//  3. Clearer in code: crawler.NewSpider() vs crawler.NewCrawler()
type Spider struct {
	// client is the HTTP client configured for Tor proxy.
	client *http.Client

	// maxDepth limits how deep to crawl from the starting URL.
	// 0 means only the starting page, 1 means one level of links, etc.
	maxDepth int

	// maxPages limits the total number of pages to crawl.
	// This prevents runaway crawling on large sites.
	maxPages int

	// delay is the time to wait between requests.
	// This is a politeness setting to avoid overwhelming servers.
	delay time.Duration

	// userAgent is the User-Agent header to use.
	userAgent string

	// maxBodySize limits the size of response bodies to read.
	maxBodySize int64

	// ignorePatterns are URL path patterns to skip during crawling.
	// Patterns use glob syntax (e.g., "/admin/*", "*.pdf").
	ignorePatterns []string

	// followPatterns are URL path patterns to follow during crawling.
	// If set, only URLs matching these patterns are crawled.
	// Empty means all URLs are allowed (subject to ignorePatterns).
	followPatterns []string

	// visited tracks URLs already visited to avoid duplicates.
	visited map[string]bool

	// mutex protects concurrent access to visited.
	mutex sync.Mutex

	// pageCount tracks pages crawled.
	pageCount int
}

// SpiderOption configures a Spider.
type SpiderOption func(*Spider)

// WithMaxDepth sets the maximum crawl depth.
// 0 = only the starting page, 1 = starting page plus linked pages, etc.
func WithMaxDepth(depth int) SpiderOption {
	return func(s *Spider) {
		s.maxDepth = depth
	}
}

// WithMaxPages sets the maximum number of pages to crawl.
func WithMaxPages(maxPages int) SpiderOption {
	return func(s *Spider) {
		s.maxPages = maxPages
	}
}

// WithDelay sets the delay between requests.
func WithDelay(d time.Duration) SpiderOption {
	return func(s *Spider) {
		s.delay = d
	}
}

// WithSpiderUserAgent sets a custom User-Agent header.
func WithSpiderUserAgent(ua string) SpiderOption {
	return func(s *Spider) {
		s.userAgent = ua
	}
}

// WithSpiderMaxBodySize sets the maximum response body size.
func WithSpiderMaxBodySize(size int64) SpiderOption {
	return func(s *Spider) {
		s.maxBodySize = size
	}
}

// WithIgnorePatterns sets URL path patterns to skip during crawling.
// Patterns use glob syntax (e.g., "/admin/*", "*.pdf", "/logout*").
// URLs matching any of these patterns will not be crawled.
func WithIgnorePatterns(patterns []string) SpiderOption {
	return func(s *Spider) {
		s.ignorePatterns = patterns
	}
}

// WithFollowPatterns sets URL path patterns to follow during crawling.
// Patterns use glob syntax (e.g., "/api/*", "/public/*").
// If set, only URLs matching at least one pattern are crawled.
// Empty slice means all URLs are allowed (default behavior).
func WithFollowPatterns(patterns []string) SpiderOption {
	return func(s *Spider) {
		s.followPatterns = patterns
	}
}

// NewSpider creates a new Spider with the given HTTP client.
// The client should be pre-configured with the Tor SOCKS5 proxy.
//
// Design decision: We require an external client because:
//  1. Tor proxy configuration is handled by the tor package
//  2. Consistent with protocol scanners
//  3. Allows for different configurations in tests
func NewSpider(client *http.Client, opts ...SpiderOption) *Spider {
	s := &Spider{
		client:      client,
		maxDepth:    5,
		maxPages:    100,
		delay:       1 * time.Second,
		userAgent:   "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
		maxBodySize: 10 * 1024 * 1024, // 10MB
		visited:     make(map[string]bool),
		pageCount:   0,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Crawl starts crawling from the given URL and returns all discovered pages.
//
// Design decision: We return a slice of pages rather than using a callback
// because:
//  1. Simpler API for callers
//  2. Pages are small relative to total memory
//  3. Caller can process all at once or iterate as needed
func (s *Spider) Crawl(ctx context.Context, startURL string) ([]*model.Page, error) {
	// Normalize and validate start URL
	start, err := url.Parse(startURL)
	if err != nil {
		return nil, fmt.Errorf("invalid start URL: %w", err)
	}

	// Ensure it's an HTTP(S) URL
	if start.Scheme != "http" && start.Scheme != "https" {
		start.Scheme = "http"
	}

	// Initialize crawl state
	pages := make([]*model.Page, 0)
	queue := make([]queueItem, 0)
	queue = append(queue, queueItem{url: start.String(), depth: 0})

	// Process queue
	for len(queue) > 0 && s.pageCount < s.maxPages {
		// Check context
		select {
		case <-ctx.Done():
			return pages, ctx.Err()
		default:
		}

		// Pop from queue
		item := queue[0]
		queue = queue[1:]

		// Skip if already visited
		if s.isVisited(item.url) {
			continue
		}
		s.markVisited(item.url)

		// Fetch and parse page
		page, links, err := s.fetchPage(ctx, item.url)
		if err != nil {
			// Log but continue - some pages will fail
			continue
		}

		pages = append(pages, page)
		s.pageCount++

		// Add new links to queue if within depth limit
		if item.depth < s.maxDepth {
			for _, link := range links {
				if !s.isVisited(link) && s.isSameService(start.Host, link) && s.shouldCrawl(link) {
					queue = append(queue, queueItem{url: link, depth: item.depth + 1})
				}
			}
		}

		// Politeness delay
		if s.delay > 0 && len(queue) > 0 {
			select {
			case <-ctx.Done():
				return pages, ctx.Err()
			case <-time.After(s.delay):
			}
		}
	}

	return pages, nil
}

// queueItem represents an item in the crawl queue.
type queueItem struct {
	url   string
	depth int
}

// fetchPage fetches a single page and extracts its content and links.
func (s *Spider) fetchPage(ctx context.Context, pageURL string) (*model.Page, []string, error) {
	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	// Perform request
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	// Read body with limit
	bodyReader := io.LimitReader(resp.Body, s.maxBodySize)
	body, err := io.ReadAll(bodyReader)
	if err != nil {
		return nil, nil, err
	}

	// Parse URL
	u, err := url.Parse(pageURL)
	if err != nil {
		return nil, nil, err
	}

	// Create page model
	// Note: model.Page uses Raw for bytes and Hash for content hash
	page := &model.Page{
		URL:         pageURL,
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Raw:         body,
		Snapshot:    string(body),
		Headers:     resp.Header,
	}

	// Compute hash and enforce size limits
	page.ComputeHash()
	page.TruncateSnapshot()
	page.TruncateRaw()

	// Extract links if HTML
	var links []string
	if strings.Contains(page.ContentType, "text/html") {
		parser, err := NewParser(pageURL)
		if err == nil {
			result, err := parser.Parse(strings.NewReader(string(body)))
			if err == nil {
				page.Title = result.Title
				links = result.InternalLinks
			}
		}
	}

	// Note: OnionService is tracked externally by the caller
	// The model.Page structure doesn't have this field
	_ = u.Host // Used for same-service checks in caller

	return page, links, nil
}

// isVisited checks if a URL has been visited.
func (s *Spider) isVisited(pageURL string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.visited[s.normalizeURL(pageURL)]
}

// markVisited marks a URL as visited.
func (s *Spider) markVisited(pageURL string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.visited[s.normalizeURL(pageURL)] = true
}

// normalizeURL normalizes a URL for deduplication.
//
// Design decision: We normalize URLs because:
//  1. Same page can have different URL representations
//  2. Fragment (#anchor) doesn't change content
//  3. Trailing slashes may or may not be significant
func (s *Spider) normalizeURL(pageURL string) string {
	u, err := url.Parse(pageURL)
	if err != nil {
		return pageURL
	}

	// Remove fragment
	u.Fragment = ""

	// Normalize scheme to lowercase
	u.Scheme = strings.ToLower(u.Scheme)

	// Normalize host to lowercase
	u.Host = strings.ToLower(u.Host)

	// Normalize root path (empty path and "/" are equivalent)
	// This handles the common case where http://example.com and
	// http://example.com/ should be treated as the same URL
	if u.Path == "" {
		u.Path = "/"
	}

	return u.String()
}

// isSameService checks if a URL is part of the same onion service.
//
// Design decision: We only crawl the same service by default because:
//  1. Crawling other services could be seen as unauthorized
//  2. Keeps the crawl focused on the target
//  3. Cross-service links are tracked separately for correlation
func (s *Spider) isSameService(baseHost, targetURL string) bool {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	return strings.EqualFold(u.Host, baseHost)
}

// Reset clears the spider's state, allowing it to be reused.
func (s *Spider) Reset() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.visited = make(map[string]bool)
	s.pageCount = 0
}

// Stats returns current crawl statistics.
func (s *Spider) Stats() SpiderStats {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return SpiderStats{
		PagesVisited: s.pageCount,
		URLsQueued:   len(s.visited),
	}
}

// SpiderStats contains crawl statistics.
type SpiderStats struct {
	// PagesVisited is the number of pages successfully crawled.
	PagesVisited int

	// URLsQueued is the number of unique URLs encountered.
	URLsQueued int
}

// shouldCrawl checks if a URL should be crawled based on ignore/follow patterns.
//
// Logic:
//  1. If URL matches any ignorePattern, skip it (return false)
//  2. If followPatterns is set and URL matches none, skip it (return false)
//  3. Otherwise, crawl it (return true)
func (s *Spider) shouldCrawl(targetURL string) bool {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	// Get the path for pattern matching
	path := u.Path
	if path == "" {
		path = "/"
	}

	// Check ignore patterns first - if matched, skip
	for _, pattern := range s.ignorePatterns {
		if matchPattern(pattern, path) {
			return false
		}
	}

	// If follow patterns are set, URL must match at least one
	if len(s.followPatterns) > 0 {
		for _, pattern := range s.followPatterns {
			if matchPattern(pattern, path) {
				return true
			}
		}
		// No follow pattern matched
		return false
	}

	// No follow patterns set, allow all (that weren't ignored)
	return true
}

// matchPattern checks if a path matches a glob pattern.
// Patterns can use:
//   - * to match any sequence of non-separator characters
//   - ** is treated as * (single segment match for simplicity)
//   - ? to match any single character
//
// Examples:
//   - "/admin/*" matches "/admin/dashboard", "/admin/users"
//   - "*.pdf" matches "/docs/file.pdf"
//   - "/api/v?" matches "/api/v1", "/api/v2"
func matchPattern(pattern, path string) bool {
	// Handle common patterns more efficiently
	// For patterns like "/admin/*", we want to match "/admin/anything"
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		if strings.HasPrefix(path, prefix+"/") || path == prefix {
			return true
		}
	}

	// Handle extension patterns like "*.pdf"
	if strings.HasPrefix(pattern, "*.") {
		ext := strings.TrimPrefix(pattern, "*")
		if strings.HasSuffix(path, ext) {
			return true
		}
	}

	// Use filepath.Match for standard glob matching
	// Note: filepath.Match doesn't support ** for recursive matching,
	// but it handles * and ? well for single-segment patterns
	matched, err := filepath.Match(pattern, path)
	if err != nil {
		return false
	}
	if matched {
		return true
	}

	// Also try matching just the filename for patterns like "*.pdf"
	if strings.Contains(pattern, "*") && !strings.Contains(pattern, "/") {
		filename := filepath.Base(path)
		matched, err := filepath.Match(pattern, filename)
		if err == nil && matched {
			return true
		}
	}

	return false
}
