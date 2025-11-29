// Package crawler provides web crawling functionality for onion services.
//
// # Architecture
//
// The crawler package is designed around the Spider type, which coordinates
// the crawling process. It uses a work queue to manage URLs to visit and
// respects depth limits and politeness settings.
//
// Design decision: We implement our own crawler rather than using a third-party
// library because:
//  1. Onion services have unique requirements (Tor proxy, slow connections)
//  2. We need tight control over request timing to avoid overwhelming services
//  3. Custom parsing is needed for deanonymization-specific data extraction
//  4. Reduces external dependencies and potential security issues
//
// # Components
//
//   - Spider: The main crawler that coordinates the crawling process
//   - Parser: HTML parser that extracts links, forms, and other data
//   - Queue: URL queue with deduplication and depth tracking
//
// # Politeness
//
// The crawler is designed to be polite:
//   - Respects robots.txt (configurable)
//   - Delays between requests (configurable)
//   - Limits concurrent requests
//   - Respects max depth settings
//
// # Usage
//
//	spider := crawler.NewSpider(httpClient, crawler.WithMaxDepth(3))
//	pages, err := spider.Crawl(ctx, "http://example.onion")
//
// # Security Considerations
//
// The crawler only operates through Tor:
//   - All requests go through SOCKS5 proxy
//   - No clearnet connections are made
//   - Timeouts prevent hanging on slow services
//   - Memory limits prevent DoS from large pages
package crawler
