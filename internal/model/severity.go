package model

// Severity represents the risk level of a security finding.
// This allows categorizing findings by their potential impact on anonymity.
//
// Design decision: We use iota-based constants rather than string constants
// for efficiency in comparisons and sorting. The String() method provides
// human-readable output when needed.
type Severity int

const (
	// SeverityInfo indicates informational findings with no direct security impact.
	// Examples: cryptocurrency addresses, PGP keys, onion links.
	// These may still be useful for correlation but don't expose identity directly.
	SeverityInfo Severity = iota

	// SeverityLow indicates minor issues with limited impact.
	// Examples: EXIF metadata, SSH fingerprints.
	// These could potentially be used for correlation but require additional data.
	SeverityLow

	// SeverityMedium indicates moderate issues that warrant attention.
	// Examples: email addresses, social media links, open directories.
	// These provide identity clues that could be combined with other data.
	SeverityMedium

	// SeverityHigh indicates serious issues that significantly risk anonymity.
	// Examples: analytics trackers (GA4, Meta Pixel), external API calls, cloud services.
	// These typically involve communication with third parties who may log requests.
	SeverityHigh

	// SeverityCritical indicates severe issues that likely compromise anonymity.
	// Examples: exposed private keys, clearnet IP addresses in content.
	// These findings require immediate attention as they may fully deanonymize the service.
	SeverityCritical
)

// String returns a human-readable representation of the severity level.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// FindingInfo contains metadata about a finding type including severity,
// impact description, and remediation recommendation.
type FindingInfo struct {
	Severity       Severity
	Impact         string
	Recommendation string
}

// findingInfoMapping maps finding types to their metadata.
// This centralized mapping ensures consistent risk assessment across the application.
//
// Design decision: We use a map rather than embedding severity in each finding type
// because:
// 1. It allows updating risk assessments without modifying type definitions
// 2. It provides a single source of truth for risk levels
// 3. It makes it easy to generate severity documentation
var findingInfoMapping = map[string]FindingInfo{
	// CRITICAL - Immediate anonymity compromise
	"private_key_v3": {
		Severity:       SeverityCritical,
		Impact:         "The Tor hidden service private key is exposed, allowing attackers to impersonate the service or decrypt traffic.",
		Recommendation: "Immediately rotate the hidden service keys and remove the exposed key file from public access.",
	},
	"private_key_v2": {
		Severity:       SeverityCritical,
		Impact:         "The Tor hidden service private key is exposed. V2 onion services are deprecated and insecure.",
		Recommendation: "Migrate to V3 onion services immediately and rotate all keys.",
	},
	"clearnet_ip": {
		Severity:       SeverityCritical,
		Impact:         "A clearnet IP address was found, potentially revealing the server's real location and identity.",
		Recommendation: "Remove all references to clearnet IP addresses. Audit server configuration to prevent IP leaks.",
	},
	"hostname_file": {
		Severity:       SeverityCritical,
		Impact:         "The hostname file is publicly accessible, potentially exposing service configuration details.",
		Recommendation: "Restrict access to the hostname file and review web server configuration.",
	},
	"ed25519_secret_key": {
		Severity:       SeverityCritical,
		Impact:         "Ed25519 secret key is exposed, compromising the cryptographic identity of the service.",
		Recommendation: "Immediately generate new keys and revoke any associated credentials.",
	},

	// HIGH - Significant anonymity risk
	"apache_mod_status": {
		Severity:       SeverityHigh,
		Impact:         "Apache mod_status exposes server internals including IP addresses, request patterns, and server load.",
		Recommendation: "Disable mod_status or restrict access to localhost only.",
	},
	"nginx_status": {
		Severity:       SeverityHigh,
		Impact:         "Nginx status page exposes server metrics that can be used for fingerprinting.",
		Recommendation: "Disable the status page or restrict access to authenticated users.",
	},
	"google_analytics_ga4": {
		Severity:       SeverityHigh,
		Impact:         "Google Analytics sends visitor data to Google servers, potentially correlating Tor users.",
		Recommendation: "Remove Google Analytics. Use self-hosted analytics like Matomo with anonymization enabled.",
	},
	"google_analytics_ua": {
		Severity:       SeverityHigh,
		Impact:         "Google Analytics (Universal Analytics) sends visitor data to Google, enabling user tracking.",
		Recommendation: "Remove Google Analytics. Consider privacy-preserving alternatives.",
	},
	"meta_pixel": {
		Severity:       SeverityHigh,
		Impact:         "Meta Pixel tracks users and sends data to Facebook/Meta servers.",
		Recommendation: "Remove Meta Pixel to protect user privacy.",
	},
	"cloudflare_detected": {
		Severity:       SeverityHigh,
		Impact:         "Cloudflare acts as a man-in-the-middle and can see all traffic, potentially logging real IPs.",
		Recommendation: "Avoid using Cloudflare for anonymous services. Host directly via Tor.",
	},
	"aws_s3": {
		Severity:       SeverityHigh,
		Impact:         "AWS S3 bucket usage links the service to an AWS account, potentially revealing identity.",
		Recommendation: "Self-host static assets or use anonymous hosting alternatives.",
	},
	"aws_cloudfront": {
		Severity:       SeverityHigh,
		Impact:         "CloudFront CDN links the service to an AWS account and logs access.",
		Recommendation: "Avoid AWS services. Self-host all content through Tor.",
	},
	"aws_apigateway": {
		Severity:       SeverityHigh,
		Impact:         "AWS API Gateway links the service to an AWS account with detailed access logs.",
		Recommendation: "Host APIs directly on the hidden service without AWS intermediaries.",
	},
	"external_api": {
		Severity:       SeverityHigh,
		Impact:         "External API calls may leak visitor information and link users to the service.",
		Recommendation: "Proxy all external API calls through the server or eliminate external dependencies.",
	},
	"csp_external_domains": {
		Severity:       SeverityHigh,
		Impact:         "CSP references external domains that will receive requests from visitors.",
		Recommendation: "Self-host all resources and update CSP to only allow same-origin content.",
	},
	"redis_unauthenticated": {
		Severity:       SeverityHigh,
		Impact:         "Unauthenticated Redis allows data theft and potential remote code execution.",
		Recommendation: "Enable Redis authentication and bind to localhost only.",
	},
	"mongodb_open": {
		Severity:       SeverityHigh,
		Impact:         "Open MongoDB allows unauthorized database access and data exfiltration.",
		Recommendation: "Enable authentication and configure firewall rules to restrict access.",
	},
	"websocket_external": {
		Severity:       SeverityHigh,
		Impact:         "External WebSocket connections can leak user data to third parties.",
		Recommendation: "Use same-origin WebSocket connections only.",
	},
	"google_fonts": {
		Severity:       SeverityHigh,
		Impact:         "Google Fonts requests reveal visitor information to Google servers.",
		Recommendation: "Self-host fonts locally instead of using Google Fonts CDN.",
	},
	"external_cdn": {
		Severity:       SeverityHigh,
		Impact:         "External CDN usage reveals visitor patterns to third-party providers.",
		Recommendation: "Self-host all static assets instead of using external CDNs.",
	},

	// MEDIUM - Moderate anonymity risk
	"email_address": {
		Severity:       SeverityMedium,
		Impact:         "Email addresses can be used to correlate identities across services.",
		Recommendation: "Use anonymous email services or remove email addresses from public pages.",
	},
	"social_telegram": {
		Severity:       SeverityMedium,
		Impact:         "Telegram links may correlate the service operator with their Telegram identity.",
		Recommendation: "Use dedicated anonymous accounts for hidden service communication.",
	},
	"social_twitter": {
		Severity:       SeverityMedium,
		Impact:         "Twitter/X links may reveal operator identity or correlate with other activities.",
		Recommendation: "Avoid linking to identifiable social media accounts.",
	},
	"social_github": {
		Severity:       SeverityMedium,
		Impact:         "GitHub links may expose developer identity and coding patterns.",
		Recommendation: "Use anonymous accounts and avoid linking personal repositories.",
	},
	"social_reddit": {
		Severity:       SeverityMedium,
		Impact:         "Reddit links may correlate with user post history and identity.",
		Recommendation: "Use dedicated anonymous accounts without post history.",
	},
	"social_matrix": {
		Severity:       SeverityMedium,
		Impact:         "Matrix links may reveal communication patterns and contacts.",
		Recommendation: "Use dedicated Matrix accounts on privacy-focused homeservers.",
	},
	"matomo_tracking": {
		Severity:       SeverityMedium,
		Impact:         "Matomo tracking collects visitor data, though typically self-hosted.",
		Recommendation: "Enable IP anonymization and minimize data collection in Matomo settings.",
	},
	"clarity_tracking": {
		Severity:       SeverityMedium,
		Impact:         "Microsoft Clarity sends session recordings to Microsoft servers.",
		Recommendation: "Remove Clarity tracking to protect visitor privacy.",
	},
	"open_directory": {
		Severity:       SeverityMedium,
		Impact:         "Open directories may expose sensitive files and internal structure.",
		Recommendation: "Disable directory listing in web server configuration.",
	},
	"server_version": {
		Severity:       SeverityMedium,
		Impact:         "Server version disclosure helps attackers identify vulnerable software.",
		Recommendation: "Configure server to hide version information in headers.",
	},
	"x_powered_by": {
		Severity:       SeverityMedium,
		Impact:         "X-Powered-By header reveals technology stack for targeted attacks.",
		Recommendation: "Remove or suppress the X-Powered-By header.",
	},
	"virtual_host": {
		Severity:       SeverityMedium,
		Impact:         "Virtual host information may reveal other services on the same server.",
		Recommendation: "Configure separate servers for each hidden service.",
	},
	"related_onion": {
		Severity:       SeverityMedium,
		Impact:         "Related onion addresses may reveal service relationships and operator identity.",
		Recommendation: "Compartmentalize services and avoid cross-referencing.",
	},
	"related_clearnet": {
		Severity:       SeverityMedium,
		Impact:         "Clearnet domain references may reveal the operator's public identity.",
		Recommendation: "Remove all clearnet references and maintain strict separation.",
	},
	"graphql_endpoint": {
		Severity:       SeverityMedium,
		Impact:         "Exposed GraphQL endpoints may leak schema and data through introspection.",
		Recommendation: "Disable introspection in production and implement proper authorization.",
	},
	"api_endpoint": {
		Severity:       SeverityMedium,
		Impact:         "Exposed API endpoints may leak internal functionality and data.",
		Recommendation: "Implement authentication and rate limiting on all API endpoints.",
	},
	"session_id_exposed": {
		Severity:       SeverityMedium,
		Impact:         "Exposed session IDs enable session hijacking attacks.",
		Recommendation: "Use secure, httpOnly cookies and implement proper session management.",
	},
	"signal_link": {
		Severity:       SeverityMedium,
		Impact:         "Signal links may correlate with phone numbers or identities.",
		Recommendation: "Use anonymous communication methods without phone number requirements.",
	},
	"session_id_link": {
		Severity:       SeverityMedium,
		Impact:         "Session IDs in URLs can be leaked via referrer headers.",
		Recommendation: "Use cookie-based sessions instead of URL parameters.",
	},
	"dread_link": {
		Severity:       SeverityMedium,
		Impact:         "Dread forum links may reveal user activity patterns.",
		Recommendation: "Use dedicated accounts without cross-referencing other identities.",
	},

	// LOW - Minor anonymity risk
	"exif_metadata": {
		Severity:       SeverityLow,
		Impact:         "EXIF metadata in images may contain location, device, or timestamp information.",
		Recommendation: "Strip EXIF metadata from all images before publishing.",
	},
	"ssh_fingerprint": {
		Severity:       SeverityLow,
		Impact:         "SSH fingerprints can be used to correlate servers across addresses.",
		Recommendation: "Generate unique SSH keys for each hidden service.",
	},
	"tls_certificate": {
		Severity:       SeverityLow,
		Impact:         "TLS certificate details may reveal organization or domain information.",
		Recommendation: "Use self-signed certificates without identifying information.",
	},
	"ftp_banner": {
		Severity:       SeverityLow,
		Impact:         "FTP banner may reveal server software and version.",
		Recommendation: "Customize or disable FTP banner messages.",
	},
	"smtp_banner": {
		Severity:       SeverityLow,
		Impact:         "SMTP banner may reveal mail server software and hostname.",
		Recommendation: "Configure generic SMTP banner without identifying information.",
	},
	"x_frame_options": {
		Severity:       SeverityLow,
		Impact:         "Missing X-Frame-Options allows clickjacking attacks.",
		Recommendation: "Add X-Frame-Options: DENY or SAMEORIGIN header.",
	},
	"server_timing": {
		Severity:       SeverityLow,
		Impact:         "Server-Timing header may leak internal performance metrics.",
		Recommendation: "Disable Server-Timing header in production.",
	},

	// INFO - No direct anonymity risk
	"bitcoin_address_legacy": {
		Severity:       SeverityInfo,
		Impact:         "Bitcoin address found. Transactions are publicly visible on the blockchain.",
		Recommendation: "Consider using privacy-focused cryptocurrencies or mixing services.",
	},
	"bitcoin_address_segwit": {
		Severity:       SeverityInfo,
		Impact:         "SegWit Bitcoin address found. Transactions are publicly visible.",
		Recommendation: "Use unique addresses for each transaction and consider privacy tools.",
	},
	"bitcoin_address_bech32": {
		Severity:       SeverityInfo,
		Impact:         "Bech32 Bitcoin address found. All transactions are blockchain-visible.",
		Recommendation: "Rotate addresses regularly and avoid address reuse.",
	},
	"bitcoin_address_taproot": {
		Severity:       SeverityInfo,
		Impact:         "Taproot Bitcoin address found with improved privacy features.",
		Recommendation: "Taproot offers better privacy but transactions remain public.",
	},
	"monero_address": {
		Severity:       SeverityInfo,
		Impact:         "Monero address found. Monero provides strong transaction privacy.",
		Recommendation: "Monero is privacy-preserving by default. No action needed.",
	},
	"ethereum_address": {
		Severity:       SeverityInfo,
		Impact:         "Ethereum address found. All transactions are publicly visible.",
		Recommendation: "Consider using privacy tools like Tornado Cash alternatives.",
	},
	"pgp_key": {
		Severity:       SeverityInfo,
		Impact:         "PGP key found. Key metadata may contain identity information.",
		Recommendation: "Use keys without real name or email in the UID.",
	},
	"onion_link_v3": {
		Severity:       SeverityInfo,
		Impact:         "V3 onion link found. May indicate related services.",
		Recommendation: "Document relationships for operational security awareness.",
	},
	"onion_link_v2": {
		Severity:       SeverityInfo,
		Impact:         "Deprecated V2 onion link found. V2 services are no longer supported.",
		Recommendation: "Update references to V3 onion addresses.",
	},
	"form_detected": {
		Severity:       SeverityInfo,
		Impact:         "Form detected. User input should be properly validated.",
		Recommendation: "Implement CSRF protection and input validation.",
	},
	"robots_txt": {
		Severity:       SeverityInfo,
		Impact:         "robots.txt found. May reveal site structure to crawlers.",
		Recommendation: "Review robots.txt for unintentionally disclosed paths.",
	},
	"sitemap_xml": {
		Severity:       SeverityInfo,
		Impact:         "Sitemap found. Reveals site structure to search engines.",
		Recommendation: "Ensure sitemap only lists intended public pages.",
	},
}

// GetSeverity returns the severity level for a finding type.
// Returns SeverityInfo if the finding type is not in the mapping.
func GetSeverity(findingType string) Severity {
	if info, ok := findingInfoMapping[findingType]; ok {
		return info.Severity
	}
	return SeverityInfo
}

// GetFindingInfo returns the full finding information for a finding type.
// Returns a default FindingInfo with SeverityInfo if the type is not in the mapping.
func GetFindingInfo(findingType string) FindingInfo {
	if info, ok := findingInfoMapping[findingType]; ok {
		return info
	}
	return FindingInfo{
		Severity:       SeverityInfo,
		Impact:         "Unknown finding type. Review manually.",
		Recommendation: "Investigate the finding and assess risk.",
	}
}
