package config

// SiteConfig holds site-specific configuration for a single onion address.
// This allows customizing crawl behavior per hidden service.
type SiteConfig struct {
	// Cookie is an HTTP cookie to use when crawling this site.
	// Format: "name=value" or "name1=value1; name2=value2"
	Cookie string `yaml:"cookie,omitempty"`

	// Headers are custom HTTP headers to include in requests to this site.
	Headers map[string]string `yaml:"headers,omitempty"`

	// Depth overrides the global crawl depth for this site.
	// If zero, the global CrawlDepth is used.
	Depth int `yaml:"depth,omitempty"`

	// IgnorePatterns are URL patterns to skip during crawling.
	// Patterns are matched against the URL path using glob syntax.
	IgnorePatterns []string `yaml:"ignorePatterns,omitempty"`

	// FollowPatterns are URL patterns to follow during crawling.
	// If specified, only URLs matching these patterns are crawled.
	FollowPatterns []string `yaml:"followPatterns,omitempty"`
}

// File represents the structure of the .onionscan configuration file.
type File struct {
	// Sites maps onion addresses to their site-specific configurations.
	// Keys should be the onion address without the protocol (e.g., "example.onion").
	Sites map[string]SiteConfig `yaml:"sites,omitempty"`

	// Defaults contains default site configuration applied to all sites
	// unless overridden in the site-specific configuration.
	Defaults SiteConfig `yaml:"defaults,omitempty"`
}

// GetSiteConfig returns the configuration for a specific onion address.
// It merges the site-specific configuration with defaults.
func (cf *File) GetSiteConfig(onionAddress string) SiteConfig {
	// Start with defaults
	result := cf.Defaults

	// Override with site-specific configuration if present
	if siteConfig, ok := cf.Sites[onionAddress]; ok {
		if siteConfig.Cookie != "" {
			result.Cookie = siteConfig.Cookie
		}
		if siteConfig.Depth != 0 {
			result.Depth = siteConfig.Depth
		}
		if len(siteConfig.Headers) > 0 {
			if result.Headers == nil {
				result.Headers = make(map[string]string)
			}
			for k, v := range siteConfig.Headers {
				result.Headers[k] = v
			}
		}
		if len(siteConfig.IgnorePatterns) > 0 {
			result.IgnorePatterns = siteConfig.IgnorePatterns
		}
		if len(siteConfig.FollowPatterns) > 0 {
			result.FollowPatterns = siteConfig.FollowPatterns
		}
	}

	return result
}
