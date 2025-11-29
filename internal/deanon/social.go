package deanon

import (
	"context"
	"regexp"
	"strings"

	"github.com/nao1215/onionscan/internal/model"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// SocialAnalyzer detects social media links and profiles.
// Social media accounts are strong identity vectors that can link
// a hidden service operator to their real identity.
//
// This analyzer checks for:
//   - Twitter/X profiles and posts
//   - Facebook profiles and pages
//   - Instagram profiles
//   - LinkedIn profiles
//   - GitHub profiles and repositories
//   - YouTube channels
//   - Telegram channels and groups
//   - Discord invites
//   - Reddit profiles
//   - Other social platforms
type SocialAnalyzer struct {
	// patterns maps platform names to detection patterns
	patterns map[string]*socialPattern
}

// socialPattern holds detection info for a social platform.
type socialPattern struct {
	urlPatterns   []*regexp.Regexp
	handlePattern *regexp.Regexp
	severity      model.Severity
	description   string
}

// NewSocialAnalyzer creates a new SocialAnalyzer.
func NewSocialAnalyzer() *SocialAnalyzer {
	return &SocialAnalyzer{
		patterns: map[string]*socialPattern{
			"twitter": {
				urlPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)https?://(?:www\.)?(?:twitter\.com|x\.com)/([A-Za-z0-9_]{1,15})(?:/|$|\?)`),
					regexp.MustCompile(`(?i)https?://(?:www\.)?(?:twitter\.com|x\.com)/([A-Za-z0-9_]{1,15})/status/\d+`),
				},
				handlePattern: regexp.MustCompile(`(?i)(?:^|[^\w])@([A-Za-z0-9_]{1,15})(?:[^\w]|$)`),
				severity:      model.SeverityHigh,
				description:   "A Twitter/X profile or post link was found. This is a strong identity vector.",
			},
			"facebook": {
				urlPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)https?://(?:www\.)?facebook\.com/([A-Za-z0-9.]+)(?:/|$|\?)`),
					regexp.MustCompile(`(?i)https?://(?:www\.)?fb\.com/([A-Za-z0-9.]+)(?:/|$|\?)`),
					regexp.MustCompile(`(?i)https?://(?:www\.)?facebook\.com/profile\.php\?id=(\d+)`),
				},
				severity:    model.SeverityHigh,
				description: "A Facebook profile or page link was found. This is a strong identity vector.",
			},
			"instagram": {
				urlPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)https?://(?:www\.)?instagram\.com/([A-Za-z0-9_.]+)(?:/|$|\?)`),
					regexp.MustCompile(`(?i)https?://(?:www\.)?instagr\.am/([A-Za-z0-9_.]+)(?:/|$|\?)`),
				},
				severity:    model.SeverityHigh,
				description: "An Instagram profile link was found. This is a strong identity vector.",
			},
			"linkedin": {
				urlPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)https?://(?:www\.)?linkedin\.com/in/([A-Za-z0-9_-]+)(?:/|$|\?)`),
					regexp.MustCompile(`(?i)https?://(?:www\.)?linkedin\.com/company/([A-Za-z0-9_-]+)(?:/|$|\?)`),
				},
				severity:    model.SeverityCritical,
				description: "A LinkedIn profile or company link was found. This is a critical identity vector often linked to real names.",
			},
			"github": {
				urlPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)https?://(?:www\.)?github\.com/([A-Za-z0-9_-]+)(?:/|$|\?)`),
					regexp.MustCompile(`(?i)https?://(?:www\.)?github\.com/([A-Za-z0-9_-]+)/([A-Za-z0-9_.-]+)`),
					regexp.MustCompile(`(?i)https?://gist\.github\.com/([A-Za-z0-9_-]+)`),
				},
				severity:    model.SeverityHigh,
				description: "A GitHub profile or repository link was found. This can reveal coding style and identity.",
			},
			"youtube": {
				urlPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)https?://(?:www\.)?youtube\.com/(?:channel|c|user)/([A-Za-z0-9_-]+)`),
					regexp.MustCompile(`(?i)https?://(?:www\.)?youtube\.com/@([A-Za-z0-9_-]+)`),
					regexp.MustCompile(`(?i)https?://youtu\.be/([A-Za-z0-9_-]+)`),
				},
				severity:    model.SeverityHigh,
				description: "A YouTube channel or video link was found. This can reveal identity through voice or content.",
			},
			"telegram": {
				urlPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)https?://(?:www\.)?t\.me/([A-Za-z0-9_]+)`),
					regexp.MustCompile(`(?i)https?://(?:www\.)?telegram\.me/([A-Za-z0-9_]+)`),
					regexp.MustCompile(`(?i)tg://resolve\?domain=([A-Za-z0-9_]+)`),
				},
				severity:    model.SeverityMedium,
				description: "A Telegram channel, group, or user link was found.",
			},
			"discord": {
				urlPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)https?://(?:www\.)?discord\.gg/([A-Za-z0-9]+)`),
					regexp.MustCompile(`(?i)https?://(?:www\.)?discord\.com/invite/([A-Za-z0-9]+)`),
					regexp.MustCompile(`(?i)https?://(?:www\.)?discordapp\.com/invite/([A-Za-z0-9]+)`),
				},
				severity:    model.SeverityMedium,
				description: "A Discord invite link was found. This can lead to identity exposure through server membership.",
			},
			"reddit": {
				urlPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)https?://(?:www\.)?reddit\.com/user/([A-Za-z0-9_-]+)`),
					regexp.MustCompile(`(?i)https?://(?:www\.)?reddit\.com/r/([A-Za-z0-9_]+)`),
				},
				severity:    model.SeverityMedium,
				description: "A Reddit profile or subreddit link was found.",
			},
			"tiktok": {
				urlPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)https?://(?:www\.)?tiktok\.com/@([A-Za-z0-9_.]+)`),
				},
				severity:    model.SeverityHigh,
				description: "A TikTok profile link was found. This is a strong identity vector.",
			},
			"mastodon": {
				urlPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)https?://[A-Za-z0-9.-]+/@([A-Za-z0-9_]+)`),
				},
				severity:    model.SeverityMedium,
				description: "A Mastodon/Fediverse profile link was found.",
			},
			"keybase": {
				urlPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)https?://(?:www\.)?keybase\.io/([A-Za-z0-9_]+)`),
				},
				severity:    model.SeverityHigh,
				description: "A Keybase profile link was found. Keybase often links multiple identities together.",
			},
			"signal": {
				urlPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)https?://signal\.group/[A-Za-z0-9#_-]+`),
					regexp.MustCompile(`(?i)https?://signal\.me/[A-Za-z0-9#_-]+`),
				},
				severity:    model.SeverityMedium,
				description: "A Signal group or contact link was found.",
			},
			"whatsapp": {
				urlPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)https?://(?:www\.)?wa\.me/(\d+)`),
					regexp.MustCompile(`(?i)https?://(?:www\.)?chat\.whatsapp\.com/([A-Za-z0-9]+)`),
				},
				severity:    model.SeverityHigh,
				description: "A WhatsApp contact or group link was found. This reveals phone numbers.",
			},
			"patreon": {
				urlPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)https?://(?:www\.)?patreon\.com/([A-Za-z0-9_]+)`),
				},
				severity:    model.SeverityHigh,
				description: "A Patreon profile link was found. This can link to financial identity.",
			},
			"medium": {
				urlPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)https?://(?:www\.)?medium\.com/@([A-Za-z0-9_.-]+)`),
					regexp.MustCompile(`(?i)https?://([A-Za-z0-9_-]+)\.medium\.com`),
				},
				severity:    model.SeverityMedium,
				description: "A Medium profile link was found.",
			},
		},
	}
}

// Name returns the analyzer name.
func (a *SocialAnalyzer) Name() string {
	return "social"
}

// Category returns the analyzer category.
func (a *SocialAnalyzer) Category() string {
	return CategoryIdentity
}

// Analyze searches for social media links in crawled pages.
func (a *SocialAnalyzer) Analyze(ctx context.Context, data *AnalysisData) ([]model.Finding, error) {
	findings := make([]model.Finding, 0)
	foundLinks := make(map[string]bool) // Deduplicate findings

	for _, page := range data.Pages {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Search in page content
		for platform, pattern := range a.patterns {
			pageFindings := a.searchPlatform(platform, pattern, page)
			for _, f := range pageFindings {
				key := f.Type + "|" + f.Value
				if !foundLinks[key] {
					foundLinks[key] = true
					findings = append(findings, f)
				}
			}
		}
	}

	return findings, nil
}

// searchPlatform searches for a specific platform's patterns.
func (a *SocialAnalyzer) searchPlatform(platform string, pattern *socialPattern, page *model.Page) []model.Finding {
	findings := make([]model.Finding, 0)

	content := page.Snapshot

	// Search URL patterns
	for _, urlPattern := range pattern.urlPatterns {
		matches := urlPattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 0 {
				// Filter out common false positives
				if a.isValidSocialLink(platform, match[0]) {
					identifier := ""
					if len(match) > 1 {
						identifier = match[1]
					}

					findings = append(findings, model.Finding{
						Type:         "social_" + platform,
						Title:        a.titleForPlatform(platform) + " Link Found",
						Description:  pattern.description,
						Severity:     pattern.severity,
						SeverityText: pattern.severity.String(),
						Value:        a.sanitizeValue(match[0], identifier),
						Location:     page.URL,
					})
				}
			}
		}
	}

	// Search for @handles (Twitter specific)
	if pattern.handlePattern != nil && platform == "twitter" {
		// Only look for handles in visible text areas, not in URLs
		handles := pattern.handlePattern.FindAllStringSubmatch(content, -1)
		seenHandles := make(map[string]bool)
		for _, match := range handles {
			if len(match) > 1 {
				handle := strings.ToLower(match[1])
				// Filter out common words that might match
				if !a.isCommonWord(handle) && !seenHandles[handle] {
					seenHandles[handle] = true
					findings = append(findings, model.Finding{
						Type:         "social_twitter_handle",
						Title:        "Twitter/X Handle Reference Found",
						Description:  "A Twitter/X @handle reference was found. This could indicate operator identity.",
						Severity:     model.SeverityMedium,
						SeverityText: model.SeverityMedium.String(),
						Value:        "@" + match[1],
						Location:     page.URL,
					})
				}
			}
		}
	}

	return findings
}

// isValidSocialLink filters out false positives.
func (a *SocialAnalyzer) isValidSocialLink(_, url string) bool {
	lower := strings.ToLower(url)

	// Filter out common false positives
	invalidPaths := []string{
		"/intent/", "/share", "/sharer", "/login", "/signup", "/register",
		"/help", "/about", "/terms", "/privacy", "/settings", "/search",
		"/home", "/explore", "/notifications", "/messages", "/i/",
		"example.com", "placeholder", "username", "yourname",
	}

	for _, invalid := range invalidPaths {
		if strings.Contains(lower, invalid) {
			return false
		}
	}

	return true
}

// isCommonWord returns true if the string is a common word, not a handle.
func (a *SocialAnalyzer) isCommonWord(s string) bool {
	commonWords := map[string]bool{
		"the": true, "and": true, "for": true, "are": true, "but": true,
		"not": true, "you": true, "all": true, "can": true, "her": true,
		"was": true, "one": true, "our": true, "out": true, "has": true,
		"media": true, "here": true, "twitter": true, "facebook": true,
		"instagram": true, "email": true, "contact": true, "admin": true,
		"support": true, "info": true, "help": true, "null": true,
		"undefined": true, "anonymous": true, "example": true,
	}
	return commonWords[strings.ToLower(s)]
}

// titleForPlatform returns a display title for a platform.
func (a *SocialAnalyzer) titleForPlatform(platform string) string {
	titles := map[string]string{
		"twitter":   "Twitter/X",
		"facebook":  "Facebook",
		"instagram": "Instagram",
		"linkedin":  "LinkedIn",
		"github":    "GitHub",
		"youtube":   "YouTube",
		"telegram":  "Telegram",
		"discord":   "Discord",
		"reddit":    "Reddit",
		"tiktok":    "TikTok",
		"mastodon":  "Mastodon",
		"keybase":   "Keybase",
		"signal":    "Signal",
		"whatsapp":  "WhatsApp",
		"patreon":   "Patreon",
		"medium":    "Medium",
	}

	if title, ok := titles[platform]; ok {
		return title
	}
	return cases.Title(language.English).String(platform)
}

// sanitizeValue returns a safe representation of the social link.
func (a *SocialAnalyzer) sanitizeValue(url, _ string) string {
	// For most cases, we can show the full URL
	// But truncate very long ones
	if len(url) > 100 {
		return url[:100] + "..."
	}
	return url
}

// Ensure SocialAnalyzer implements CheckAnalyzer.
var _ CheckAnalyzer = (*SocialAnalyzer)(nil)
