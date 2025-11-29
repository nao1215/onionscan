package model

// AnonymityReport contains detailed findings about anonymity risks.
// This is a sub-structure of OnionScanReport that groups all identity-related findings.
//
// Design decision: We group all anonymity findings in a separate struct to:
// 1. Keep the main report struct more manageable
// 2. Allow for easier analysis of just the anonymity-related data
// 3. Potentially serialize this separately for privacy-focused reporting
type AnonymityReport struct {
	// === Related Services ===

	// RelatedOnionServices contains other .onion addresses linked to this service.
	// Links may be found in content, configuration files, or cross-references.
	RelatedOnionServices []OnionLink `json:"related_onion_services,omitempty"`

	// RelatedClearnetDomains contains clearnet domains linked to this service.
	// These are potential deanonymization vectors.
	RelatedClearnetDomains []string `json:"related_clearnet_domains,omitempty"`

	// === Identity Information ===

	// IPAddresses contains any IP addresses found in content or headers.
	// Finding a clearnet IP is a critical anonymity failure.
	IPAddresses []string `json:"ip_addresses,omitempty"`

	// EmailAddresses contains email addresses found on the service.
	EmailAddresses []string `json:"email_addresses,omitempty"`

	// LinkedOnions contains all onion links found in content.
	// These may indicate related services or communities.
	LinkedOnions []OnionLink `json:"linked_onions,omitempty"`

	// === Cryptocurrency Addresses ===

	// BitcoinAddresses contains Bitcoin addresses found on the service.
	BitcoinAddresses []CryptoAddress `json:"bitcoin_addresses,omitempty"`

	// MoneroAddresses contains Monero addresses found on the service.
	MoneroAddresses []CryptoAddress `json:"monero_addresses,omitempty"`

	// EthereumAddresses contains Ethereum addresses found on the service.
	EthereumAddresses []CryptoAddress `json:"ethereum_addresses,omitempty"`

	// === Analytics and Tracking ===

	// AnalyticsIDs contains detected analytics/tracking identifiers.
	// These represent significant anonymity risks as they typically
	// involve requests to third-party servers.
	AnalyticsIDs []AnalyticsID `json:"analytics_ids,omitempty"` //nolint:tagliatelle // IDs is standard acronym

	// === Cloud Services ===

	// CloudflareDetected indicates if Cloudflare is being used.
	// Using Cloudflare means the real IP may be exposed to Cloudflare.
	CloudflareDetected bool `json:"cloudflare_detected"`

	// CloudflareRayID is the Cloudflare Ray ID if detected.
	CloudflareRayID string `json:"cloudflare_ray_id,omitempty"`

	// AWSResources contains detected AWS resource references.
	AWSResources []AWSResource `json:"aws_resources,omitempty"`

	// === Content Security Policy ===

	// CSPExternalDomains contains external domains found in CSP headers.
	// These indicate intentional external communication.
	CSPExternalDomains []string `json:"csp_external_domains,omitempty"`

	// === API and Network ===

	// APIEndpoints contains detected external API endpoints.
	// Found in JavaScript fetch/axios calls, WebSocket connections, etc.
	APIEndpoints []APIEndpoint `json:"api_endpoints,omitempty"`

	// === Social Media ===

	// SocialLinks contains social media profile links found on the service.
	SocialLinks []SocialLink `json:"social_links,omitempty"`

	// === Server Information Leakage ===

	// ServerVersion is the Server header value if present.
	// Reveals web server software and version.
	ServerVersion string `json:"server_version,omitempty"`

	// XPoweredBy is the X-Powered-By header value if present.
	// Reveals backend technology stack.
	XPoweredBy string `json:"x_powered_by,omitempty"`

	// VirtualHosts contains hostnames found in configuration.
	// May reveal clearnet domains or other hidden services.
	VirtualHosts []string `json:"virtual_hosts,omitempty"`

	// === Metadata ===

	// ExifImages contains images with EXIF metadata.
	// EXIF can contain GPS coordinates, device info, etc.
	ExifImages []ExifData `json:"exif_images,omitempty"`

	// === Exposed Files ===

	// OpenDirectories contains URLs of directory listings.
	OpenDirectories []string `json:"open_directories,omitempty"`

	// PrivateKeyExposed indicates if a private key file was found.
	PrivateKeyExposed bool `json:"private_key_exposed"`

	// PrivateKeyType indicates the type of exposed private key.
	// Values: "v2_rsa" (RSA-1024, deprecated) or "v3_ed25519" (Ed25519).
	PrivateKeyType string `json:"private_key_type,omitempty"`

	// HostnameFileExposed indicates if the hostname file was found.
	// This file contains the .onion address and shouldn't be public.
	HostnameFileExposed bool `json:"hostname_file_exposed"`

	// === Server Status ===

	// ApacheModStatusFound indicates if Apache mod_status was found.
	ApacheModStatusFound bool `json:"apache_mod_status_found"`

	// NginxStatusFound indicates if nginx status page was found.
	NginxStatusFound bool `json:"nginx_status_found"`
}

// OnionLink represents a discovered onion address with metadata.
type OnionLink struct {
	// Address is the .onion address.
	Address string `json:"address"`

	// Version is the onion address version (2 or 3).
	Version int `json:"version"`

	// Deprecated indicates if this is a v2 address (deprecated in 2021).
	Deprecated bool `json:"deprecated,omitempty"`

	// Context describes where this address was found.
	Context string `json:"context,omitempty"`
}

// CryptoAddress represents a cryptocurrency address with type information.
type CryptoAddress struct {
	// Address is the cryptocurrency address string.
	Address string `json:"address"`

	// Type indicates the address format.
	// Bitcoin: "legacy" (1...), "p2sh" (3...), "bech32" (bc1q...), "taproot" (bc1p...)
	// Monero: "standard", "integrated"
	// Ethereum: "standard"
	Type string `json:"type"`

	// ChecksumValid indicates if address checksum was verified.
	// Some formats (like Monero) have complex checksums we may not verify.
	ChecksumValid bool `json:"checksum_valid"`

	// Context describes where this address was found.
	Context string `json:"context,omitempty"`
}

// AnalyticsID represents a detected analytics/tracking identifier.
type AnalyticsID struct {
	// ID is the tracking identifier.
	ID string `json:"id"`

	// Type indicates the analytics platform.
	// Values: "ga4" (Google Analytics 4), "ua" (Universal Analytics),
	// "meta_pixel", "matomo", "clarity" (Microsoft Clarity).
	Type string `json:"type"`

	// ServerURL is the analytics server URL (for self-hosted like Matomo).
	ServerURL string `json:"server_url,omitempty"`
}

// APIEndpoint represents a detected external API endpoint.
type APIEndpoint struct {
	// URL is the API endpoint URL.
	URL string `json:"url"`

	// Type indicates how the endpoint was detected.
	// Values: "fetch", "axios", "websocket", "graphql", "xhr".
	Type string `json:"type"`

	// Risk is the assessed risk level.
	Risk Severity `json:"risk"`

	// Context describes where this endpoint was found.
	Context string `json:"context,omitempty"`
}

// SocialLink represents a social media profile link.
type SocialLink struct {
	// Platform is the social media platform name.
	// Values: "telegram", "twitter", "x", "github", "reddit", "matrix",
	// "signal", "session", "dread".
	Platform string `json:"platform"`

	// Username is the extracted username or ID.
	Username string `json:"username"`

	// URL is the full profile URL.
	URL string `json:"url"`
}

// AWSResource represents a detected AWS resource reference.
type AWSResource struct {
	// Type is the AWS resource type.
	// Values: "s3", "cloudfront", "apigateway", "lambda".
	Type string `json:"type"`

	// Identifier is the resource identifier (bucket name, distribution ID, etc.).
	Identifier string `json:"identifier"`

	// Region is the AWS region if detected.
	Region string `json:"region,omitempty"`
}

// ExifData contains EXIF metadata extracted from an image.
type ExifData struct {
	// ImageURL is the URL of the image.
	ImageURL string `json:"image_url"`

	// Make is the camera/device manufacturer.
	Make string `json:"make,omitempty"`

	// Model is the camera/device model.
	Model string `json:"model,omitempty"`

	// Software is the software used to process the image.
	Software string `json:"software,omitempty"`

	// DateTime is when the image was taken/created.
	DateTime string `json:"datetime,omitempty"` //nolint:tagliatelle // datetime is conventional

	// GPSLatitude is the latitude if GPS data is present.
	// This is a critical finding if present.
	GPSLatitude float64 `json:"gps_latitude,omitempty"`

	// GPSLongitude is the longitude if GPS data is present.
	GPSLongitude float64 `json:"gps_longitude,omitempty"`

	// HasGPS indicates if GPS coordinates were found.
	HasGPS bool `json:"has_gps"`
}

// NewAnonymityReport creates a new empty AnonymityReport.
func NewAnonymityReport() *AnonymityReport {
	return &AnonymityReport{}
}

// AddEmailAddress adds an email address if not already present.
func (r *AnonymityReport) AddEmailAddress(email string) {
	for _, existing := range r.EmailAddresses {
		if existing == email {
			return
		}
	}
	r.EmailAddresses = append(r.EmailAddresses, email)
}

// AddIPAddress adds an IP address if not already present.
func (r *AnonymityReport) AddIPAddress(ip string) {
	for _, existing := range r.IPAddresses {
		if existing == ip {
			return
		}
	}
	r.IPAddresses = append(r.IPAddresses, ip)
}

// AddLinkedOnion adds an onion link if not already present.
func (r *AnonymityReport) AddLinkedOnion(link OnionLink) {
	for _, existing := range r.LinkedOnions {
		if existing.Address == link.Address {
			return
		}
	}
	r.LinkedOnions = append(r.LinkedOnions, link)
}

// AddBitcoinAddress adds a Bitcoin address if not already present.
func (r *AnonymityReport) AddBitcoinAddress(addr CryptoAddress) {
	for _, existing := range r.BitcoinAddresses {
		if existing.Address == addr.Address {
			return
		}
	}
	r.BitcoinAddresses = append(r.BitcoinAddresses, addr)
}

// AddMoneroAddress adds a Monero address if not already present.
func (r *AnonymityReport) AddMoneroAddress(addr CryptoAddress) {
	for _, existing := range r.MoneroAddresses {
		if existing.Address == addr.Address {
			return
		}
	}
	r.MoneroAddresses = append(r.MoneroAddresses, addr)
}

// AddEthereumAddress adds an Ethereum address if not already present.
func (r *AnonymityReport) AddEthereumAddress(addr CryptoAddress) {
	for _, existing := range r.EthereumAddresses {
		if existing.Address == addr.Address {
			return
		}
	}
	r.EthereumAddresses = append(r.EthereumAddresses, addr)
}

// AddAnalyticsID adds an analytics ID if not already present.
func (r *AnonymityReport) AddAnalyticsID(id AnalyticsID) {
	for _, existing := range r.AnalyticsIDs {
		if existing.ID == id.ID && existing.Type == id.Type {
			return
		}
	}
	r.AnalyticsIDs = append(r.AnalyticsIDs, id)
}

// AddSocialLink adds a social link if not already present.
func (r *AnonymityReport) AddSocialLink(link SocialLink) {
	for _, existing := range r.SocialLinks {
		if existing.Platform == link.Platform && existing.Username == link.Username {
			return
		}
	}
	r.SocialLinks = append(r.SocialLinks, link)
}

// AddRelatedClearnetDomain adds a clearnet domain if not already present.
// These are potential deanonymization vectors found in page content or links.
func (r *AnonymityReport) AddRelatedClearnetDomain(domain string) {
	for _, existing := range r.RelatedClearnetDomains {
		if existing == domain {
			return
		}
	}
	r.RelatedClearnetDomains = append(r.RelatedClearnetDomains, domain)
}

// HasCriticalFindings returns true if any critical severity findings exist.
func (r *AnonymityReport) HasCriticalFindings() bool {
	return r.PrivateKeyExposed ||
		r.HostnameFileExposed ||
		len(r.IPAddresses) > 0
}

// HasHighFindings returns true if any high severity findings exist.
func (r *AnonymityReport) HasHighFindings() bool {
	return r.ApacheModStatusFound ||
		r.NginxStatusFound ||
		r.CloudflareDetected ||
		len(r.AnalyticsIDs) > 0 ||
		len(r.AWSResources) > 0 ||
		len(r.CSPExternalDomains) > 0 ||
		len(r.APIEndpoints) > 0
}
