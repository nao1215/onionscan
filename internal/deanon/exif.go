package deanon

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	exif "github.com/dsoprea/go-exif/v3"

	"github.com/nao1215/onionscan/internal/model"
)

// ErrNoHTTPClient is returned when no HTTP client is configured.
var ErrNoHTTPClient = errors.New("no HTTP client configured: must use SetHTTPClient with Tor-proxied client")

// EXIFAnalyzer extracts and analyzes EXIF metadata from images.
// EXIF data can contain GPS coordinates, camera serial numbers,
// software information, and timestamps that can deanonymize operators.
//
// IMPORTANT: This analyzer requires a Tor-proxied HTTP client to be set
// via SetHTTPClient before use. It will refuse to fetch images without
// a properly configured client to prevent IP leakage.
//
// This analyzer checks for:
//   - GPS coordinates (location disclosure)
//   - Camera make/model/serial (device identification)
//   - Software information (editing software, OS)
//   - Timestamps (timezone inference)
//   - Author/copyright information (identity disclosure)
type EXIFAnalyzer struct {
	// httpClient for fetching images (MUST be Tor-proxied)
	httpClient *http.Client

	// maxImageSize limits the size of images to download (default 5MB)
	maxImageSize int64

	// imageURLPattern matches image URLs in HTML
	imageURLPattern *regexp.Regexp

	// targetHost is the .onion host being scanned (for same-origin restriction)
	targetHost string

	// allowExternalFetch enables fetching from non-target hosts (dangerous, opt-in only)
	allowExternalFetch bool
}

// NewEXIFAnalyzer creates a new EXIFAnalyzer.
// NOTE: You MUST call SetHTTPClient with a Tor-proxied client before use.
func NewEXIFAnalyzer() *EXIFAnalyzer {
	return &EXIFAnalyzer{
		httpClient:      nil,             // Must be explicitly set with Tor-proxied client
		maxImageSize:    5 * 1024 * 1024, // 5MB
		imageURLPattern: regexp.MustCompile(`(?i)\.(jpe?g|tiff?|heic)(?:\?[^"'\s]*)?$`),
	}
}

// Name returns the analyzer name.
func (a *EXIFAnalyzer) Name() string {
	return "exif"
}

// Category returns the analyzer category.
func (a *EXIFAnalyzer) Category() string {
	return CategoryIdentity
}

// Analyze extracts EXIF metadata from images found in crawled pages.
func (a *EXIFAnalyzer) Analyze(ctx context.Context, data *AnalysisData) ([]model.Finding, error) {
	// Fail closed: refuse to run without a Tor-proxied client
	if a.httpClient == nil {
		return nil, ErrNoHTTPClient
	}

	findings := make([]model.Finding, 0)
	processedImages := make(map[string]bool)

	// Set target host for same-origin restriction
	a.targetHost = data.HiddenService

	for _, page := range data.Pages {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Find image URLs in page
		imageURLs := a.extractImageURLs(page)

		for _, imgURL := range imageURLs {
			// Skip already processed images
			if processedImages[imgURL] {
				continue
			}
			processedImages[imgURL] = true

			// Only process JPEG, TIFF, HEIC (formats with EXIF support)
			if !a.imageURLPattern.MatchString(imgURL) {
				continue
			}

			// Analyze image EXIF data
			imgFindings := a.analyzeImage(ctx, imgURL, page.URL)
			findings = append(findings, imgFindings...)
		}
	}

	return findings, nil
}

// extractImageURLs extracts all image URLs from a page.
func (a *EXIFAnalyzer) extractImageURLs(page *model.Page) []string {
	urls := make([]string, 0)

	// Get images from page metadata
	for _, img := range page.Images {
		if img.Source != "" {
			urls = append(urls, img.Source)
		}
	}

	// Also search for image URLs in raw content
	imgSrcPattern := regexp.MustCompile(`(?i)<img[^>]+src\s*=\s*["']([^"']+)["']`)
	matches := imgSrcPattern.FindAllStringSubmatch(page.Snapshot, -1)
	for _, match := range matches {
		if len(match) > 1 {
			urls = append(urls, match[1])
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, u := range urls {
		if !seen[u] {
			seen[u] = true
			result = append(result, u)
		}
	}

	return result
}

// isAllowedURL checks if fetching the URL is allowed based on same-origin policy.
// Only .onion URLs from the target host are allowed by default.
func (a *EXIFAnalyzer) isAllowedURL(imageURL string) bool {
	parsed, err := url.Parse(imageURL)
	if err != nil {
		return false
	}

	host := parsed.Hostname()

	// Always allow same-origin requests to target .onion
	if host == a.targetHost {
		return true
	}

	// Check if it's a .onion URL (other onion services)
	if strings.HasSuffix(host, ".onion") {
		// Allow other .onion URLs only if external fetch is enabled
		return a.allowExternalFetch
	}

	// Clearnet URLs are never allowed (would leak IP)
	return false
}

// analyzeImage fetches an image and extracts EXIF data.
func (a *EXIFAnalyzer) analyzeImage(ctx context.Context, imageURL, pageURL string) []model.Finding {
	findings := make([]model.Finding, 0)

	// Handle data URLs (inline images, no fetch needed)
	if strings.HasPrefix(imageURL, "data:image/") {
		return a.analyzeDataURL(imageURL, pageURL)
	}

	// Skip non-HTTP URLs
	if !strings.HasPrefix(imageURL, "http://") && !strings.HasPrefix(imageURL, "https://") {
		return findings
	}

	// Security check: only fetch from allowed URLs
	if !a.isAllowedURL(imageURL) {
		// Skip silently - don't fetch from external/clearnet sources
		return findings
	}

	// Fail closed: refuse to fetch without Tor-proxied client
	if a.httpClient == nil {
		return findings
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imageURL, nil)
	if err != nil {
		return findings
	}

	// Fetch image
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	// Check content length
	if resp.ContentLength > a.maxImageSize {
		return findings
	}

	// Read image data
	limitReader := io.LimitReader(resp.Body, a.maxImageSize)
	imageData, err := io.ReadAll(limitReader)
	if err != nil {
		return findings
	}

	return a.analyzeImageData(imageData, imageURL, pageURL)
}

// analyzeDataURL extracts and analyzes EXIF from base64-encoded data URLs.
func (a *EXIFAnalyzer) analyzeDataURL(dataURL, pageURL string) []model.Finding {
	// Extract base64 data
	parts := strings.SplitN(dataURL, ",", 2)
	if len(parts) != 2 {
		return nil
	}

	// Decode base64
	imageData, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		// Try URL-safe base64
		imageData, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil
		}
	}

	return a.analyzeImageData(imageData, "data:URL", pageURL)
}

// analyzeImageData extracts EXIF data from image bytes.
func (a *EXIFAnalyzer) analyzeImageData(imageData []byte, imageURL, pageURL string) []model.Finding {
	findings := make([]model.Finding, 0)

	// Try to extract EXIF data
	rawExif, err := exif.SearchAndExtractExif(imageData)
	if err != nil || rawExif == nil {
		return findings
	}

	// Parse EXIF entries
	entries, _, err := exif.GetFlatExifData(rawExif, nil)
	if err != nil {
		return findings
	}

	// Analyze specific EXIF tags
	for _, entry := range entries {
		tagName := entry.TagName
		value := entry.Formatted

		switch tagName {
		// GPS coordinates - Critical
		case "GPSLatitude", "GPSLongitude", "GPSLatitudeRef", "GPSLongitudeRef":
			findings = append(findings, model.Finding{
				Type:         "exif_gps",
				Title:        "GPS Coordinates in Image EXIF",
				Description:  "An image contains GPS coordinates in its EXIF metadata. This reveals the location where the image was taken.",
				Severity:     model.SeverityCritical,
				SeverityText: model.SeverityCritical.String(),
				Value:        tagName + ": " + value,
				Location:     pageURL + " -> " + imageURL,
			})

		// Camera identification
		case "Make", "Model":
			findings = append(findings, model.Finding{
				Type:         "exif_camera",
				Title:        "Camera Information in Image EXIF",
				Description:  "An image contains camera make/model information. This can help identify the device used.",
				Severity:     model.SeverityMedium,
				SeverityText: model.SeverityMedium.String(),
				Value:        tagName + ": " + value,
				Location:     pageURL + " -> " + imageURL,
			})

		// Serial numbers - High severity
		case "SerialNumber", "CameraSerialNumber", "BodySerialNumber", "LensSerialNumber":
			findings = append(findings, model.Finding{
				Type:         "exif_serial",
				Title:        "Device Serial Number in Image EXIF",
				Description:  "An image contains a device serial number. This is a unique identifier that can track the device across photos.",
				Severity:     model.SeverityHigh,
				SeverityText: model.SeverityHigh.String(),
				Value:        tagName + ": " + value,
				Location:     pageURL + " -> " + imageURL,
			})

		// Software information
		case "Software", "ProcessingSoftware":
			findings = append(findings, model.Finding{
				Type:         "exif_software",
				Title:        "Software Information in Image EXIF",
				Description:  "An image contains software information that reveals editing tools or operating system used.",
				Severity:     model.SeverityLow,
				SeverityText: model.SeverityLow.String(),
				Value:        tagName + ": " + value,
				Location:     pageURL + " -> " + imageURL,
			})

		// Author/Copyright - Identity leak
		case "Artist", "Author", "Copyright", "XPAuthor":
			findings = append(findings, model.Finding{
				Type:         "exif_author",
				Title:        "Author/Copyright Information in Image EXIF",
				Description:  "An image contains author or copyright information that could identify the creator.",
				Severity:     model.SeverityHigh,
				SeverityText: model.SeverityHigh.String(),
				Value:        tagName + ": " + value,
				Location:     pageURL + " -> " + imageURL,
			})

		// DateTime - Can reveal timezone
		case "DateTimeOriginal", "DateTimeDigitized", "DateTime":
			findings = append(findings, model.Finding{
				Type:         "exif_datetime",
				Title:        "Timestamp in Image EXIF",
				Description:  "An image contains timestamp information. Combined with other data, this can help determine timezone and activity patterns.",
				Severity:     model.SeverityLow,
				SeverityText: model.SeverityLow.String(),
				Value:        tagName + ": " + value,
				Location:     pageURL + " -> " + imageURL,
			})

		// Host computer
		case "HostComputer":
			findings = append(findings, model.Finding{
				Type:         "exif_computer",
				Title:        "Host Computer in Image EXIF",
				Description:  "An image contains the name of the computer used to process it.",
				Severity:     model.SeverityMedium,
				SeverityText: model.SeverityMedium.String(),
				Value:        tagName + ": " + value,
				Location:     pageURL + " -> " + imageURL,
			})
		}
	}

	return findings
}

// SetHTTPClient sets a Tor-proxied HTTP client.
// This MUST be called before Analyze() with a properly configured Tor proxy client.
func (a *EXIFAnalyzer) SetHTTPClient(client *http.Client) {
	a.httpClient = client
}

// SetAllowExternalFetch enables fetching from non-target .onion hosts.
// WARNING: This is dangerous and should only be used when explicitly requested.
// Clearnet URLs are NEVER fetched regardless of this setting.
func (a *EXIFAnalyzer) SetAllowExternalFetch(allow bool) {
	a.allowExternalFetch = allow
}

// Ensure EXIFAnalyzer implements CheckAnalyzer.
var _ CheckAnalyzer = (*EXIFAnalyzer)(nil)
