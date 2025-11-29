package model

// platformUnknownStr is the string representation for unknown platform values.
const platformUnknownStr = "unknown"

// SocialPlatform represents a social media platform type.
type SocialPlatform string

// Social media platform constants.
const (
	// SocialPlatformUnknown represents an unknown platform.
	SocialPlatformUnknown SocialPlatform = ""
	// SocialPlatformTwitter represents Twitter/X.
	SocialPlatformTwitter SocialPlatform = "twitter"
	// SocialPlatformGitHub represents GitHub.
	SocialPlatformGitHub SocialPlatform = "github"
	// SocialPlatformTelegram represents Telegram.
	SocialPlatformTelegram SocialPlatform = "telegram"
	// SocialPlatformReddit represents Reddit.
	SocialPlatformReddit SocialPlatform = "reddit"
	// SocialPlatformMatrix represents Matrix.
	SocialPlatformMatrix SocialPlatform = "matrix"
	// SocialPlatformSignal represents Signal.
	SocialPlatformSignal SocialPlatform = "signal"
	// SocialPlatformSession represents Session.
	SocialPlatformSession SocialPlatform = "session"
	// SocialPlatformDread represents Dread.
	SocialPlatformDread SocialPlatform = "dread"
	// SocialPlatformLinkedIn represents LinkedIn.
	SocialPlatformLinkedIn SocialPlatform = "linkedin"
	// SocialPlatformFacebook represents Facebook.
	SocialPlatformFacebook SocialPlatform = "facebook"
	// SocialPlatformInstagram represents Instagram.
	SocialPlatformInstagram SocialPlatform = "instagram"
	// SocialPlatformYouTube represents YouTube.
	SocialPlatformYouTube SocialPlatform = "youtube"
	// SocialPlatformDiscord represents Discord.
	SocialPlatformDiscord SocialPlatform = "discord"
	// SocialPlatformKeybase represents Keybase.
	SocialPlatformKeybase SocialPlatform = "keybase"
	// SocialPlatformMastodon represents Mastodon.
	SocialPlatformMastodon SocialPlatform = "mastodon"
)

// String returns the string representation of the SocialPlatform.
func (p SocialPlatform) String() string {
	if p == SocialPlatformUnknown {
		return platformUnknownStr
	}
	return string(p)
}

// IsValid returns true if this is a known platform.
func (p SocialPlatform) IsValid() bool {
	switch p {
	case SocialPlatformTwitter, SocialPlatformGitHub, SocialPlatformTelegram,
		SocialPlatformReddit, SocialPlatformMatrix, SocialPlatformSignal,
		SocialPlatformSession, SocialPlatformDread, SocialPlatformLinkedIn,
		SocialPlatformFacebook, SocialPlatformInstagram, SocialPlatformYouTube,
		SocialPlatformDiscord, SocialPlatformKeybase, SocialPlatformMastodon:
		return true
	default:
		return false
	}
}

// DefaultSeverity returns the default severity for findings on this platform.
func (p SocialPlatform) DefaultSeverity() Severity {
	switch p {
	case SocialPlatformLinkedIn, SocialPlatformFacebook:
		// Real identity platforms are critical
		return SeverityCritical
	case SocialPlatformTwitter, SocialPlatformGitHub, SocialPlatformInstagram,
		SocialPlatformYouTube, SocialPlatformKeybase:
		// Pseudonymous but often linked to real identity
		return SeverityHigh
	case SocialPlatformTelegram, SocialPlatformReddit, SocialPlatformDiscord,
		SocialPlatformMastodon:
		// Typically pseudonymous
		return SeverityMedium
	case SocialPlatformMatrix, SocialPlatformSignal, SocialPlatformSession,
		SocialPlatformDread:
		// Privacy-focused platforms
		return SeverityLow
	default:
		return SeverityMedium
	}
}

// ParseSocialPlatform converts a string to SocialPlatform.
func ParseSocialPlatform(s string) SocialPlatform {
	switch s {
	case "twitter", "x":
		return SocialPlatformTwitter
	case "github":
		return SocialPlatformGitHub
	case "telegram":
		return SocialPlatformTelegram
	case "reddit":
		return SocialPlatformReddit
	case "matrix":
		return SocialPlatformMatrix
	case "signal":
		return SocialPlatformSignal
	case "session":
		return SocialPlatformSession
	case "dread":
		return SocialPlatformDread
	case "linkedin":
		return SocialPlatformLinkedIn
	case "facebook":
		return SocialPlatformFacebook
	case "instagram":
		return SocialPlatformInstagram
	case "youtube":
		return SocialPlatformYouTube
	case "discord":
		return SocialPlatformDiscord
	case "keybase":
		return SocialPlatformKeybase
	case "mastodon":
		return SocialPlatformMastodon
	default:
		return SocialPlatformUnknown
	}
}

// AnalyticsPlatform represents an analytics/tracking platform type.
type AnalyticsPlatform string

// Analytics platform constants.
const (
	// AnalyticsPlatformUnknown represents an unknown platform.
	AnalyticsPlatformUnknown AnalyticsPlatform = ""
	// AnalyticsPlatformGA4 represents Google Analytics 4.
	AnalyticsPlatformGA4 AnalyticsPlatform = "ga4"
	// AnalyticsPlatformUA represents Universal Analytics (legacy Google Analytics).
	AnalyticsPlatformUA AnalyticsPlatform = "ua"
	// AnalyticsPlatformMetaPixel represents Meta/Facebook Pixel.
	AnalyticsPlatformMetaPixel AnalyticsPlatform = "meta_pixel"
	// AnalyticsPlatformMatomo represents Matomo (self-hosted analytics).
	AnalyticsPlatformMatomo AnalyticsPlatform = "matomo"
	// AnalyticsPlatformClarity represents Microsoft Clarity.
	AnalyticsPlatformClarity AnalyticsPlatform = "clarity"
	// AnalyticsPlatformHotjar represents Hotjar.
	AnalyticsPlatformHotjar AnalyticsPlatform = "hotjar"
	// AnalyticsPlatformPlausible represents Plausible Analytics.
	AnalyticsPlatformPlausible AnalyticsPlatform = "plausible"
	// AnalyticsPlatformMixpanel represents Mixpanel.
	AnalyticsPlatformMixpanel AnalyticsPlatform = "mixpanel"
	// AnalyticsPlatformSegment represents Segment.
	AnalyticsPlatformSegment AnalyticsPlatform = "segment"
	// AnalyticsPlatformAmplitude represents Amplitude.
	AnalyticsPlatformAmplitude AnalyticsPlatform = "amplitude"
	// AnalyticsPlatformHeap represents Heap Analytics.
	AnalyticsPlatformHeap AnalyticsPlatform = "heap"
)

// String returns the string representation of the AnalyticsPlatform.
func (p AnalyticsPlatform) String() string {
	if p == AnalyticsPlatformUnknown {
		return platformUnknownStr
	}
	return string(p)
}

// IsValid returns true if this is a known platform.
func (p AnalyticsPlatform) IsValid() bool {
	switch p {
	case AnalyticsPlatformGA4, AnalyticsPlatformUA, AnalyticsPlatformMetaPixel,
		AnalyticsPlatformMatomo, AnalyticsPlatformClarity, AnalyticsPlatformHotjar,
		AnalyticsPlatformPlausible, AnalyticsPlatformMixpanel, AnalyticsPlatformSegment,
		AnalyticsPlatformAmplitude, AnalyticsPlatformHeap:
		return true
	default:
		return false
	}
}

// IsCloudBased returns true if this platform sends data to external servers.
func (p AnalyticsPlatform) IsCloudBased() bool {
	switch p {
	case AnalyticsPlatformMatomo, AnalyticsPlatformPlausible:
		// These can be self-hosted
		return false
	default:
		return true
	}
}

// DefaultSeverity returns the default severity for findings on this platform.
func (p AnalyticsPlatform) DefaultSeverity() Severity {
	switch p {
	case AnalyticsPlatformGA4, AnalyticsPlatformUA, AnalyticsPlatformMetaPixel:
		// Major tracking platforms with identity correlation
		return SeverityCritical
	case AnalyticsPlatformClarity, AnalyticsPlatformHotjar, AnalyticsPlatformMixpanel,
		AnalyticsPlatformSegment, AnalyticsPlatformAmplitude, AnalyticsPlatformHeap:
		// Cloud-based behavioral tracking
		return SeverityHigh
	case AnalyticsPlatformMatomo, AnalyticsPlatformPlausible:
		// Can be self-hosted
		return SeverityMedium
	default:
		return SeverityHigh
	}
}

// ParseAnalyticsPlatform converts a string to AnalyticsPlatform.
func ParseAnalyticsPlatform(s string) AnalyticsPlatform {
	switch s {
	case "ga4":
		return AnalyticsPlatformGA4
	case "ua":
		return AnalyticsPlatformUA
	case "meta_pixel":
		return AnalyticsPlatformMetaPixel
	case "matomo":
		return AnalyticsPlatformMatomo
	case "clarity":
		return AnalyticsPlatformClarity
	case "hotjar":
		return AnalyticsPlatformHotjar
	case "plausible":
		return AnalyticsPlatformPlausible
	case "mixpanel":
		return AnalyticsPlatformMixpanel
	case "segment":
		return AnalyticsPlatformSegment
	case "amplitude":
		return AnalyticsPlatformAmplitude
	case "heap":
		return AnalyticsPlatformHeap
	default:
		return AnalyticsPlatformUnknown
	}
}

// APIDetectionMethod represents how an API endpoint was detected.
type APIDetectionMethod string

// API detection method constants.
const (
	// APIDetectionUnknown represents an unknown detection method.
	APIDetectionUnknown APIDetectionMethod = ""
	// APIDetectionFetch represents fetch() API calls.
	APIDetectionFetch APIDetectionMethod = "fetch"
	// APIDetectionAxios represents axios library calls.
	APIDetectionAxios APIDetectionMethod = "axios"
	// APIDetectionXHR represents XMLHttpRequest calls.
	APIDetectionXHR APIDetectionMethod = "xhr"
	// APIDetectionWebSocket represents WebSocket connections.
	APIDetectionWebSocket APIDetectionMethod = "websocket"
	// APIDetectionGraphQL represents GraphQL endpoints.
	APIDetectionGraphQL APIDetectionMethod = "graphql"
	// APIDetectionSwagger represents Swagger/OpenAPI endpoints.
	APIDetectionSwagger APIDetectionMethod = "swagger"
	// APIDetectionEventSource represents Server-Sent Events.
	APIDetectionEventSource APIDetectionMethod = "eventsource"
)

// String returns the string representation of the APIDetectionMethod.
func (m APIDetectionMethod) String() string {
	if m == APIDetectionUnknown {
		return platformUnknownStr
	}
	return string(m)
}

// IsValid returns true if this is a known detection method.
func (m APIDetectionMethod) IsValid() bool {
	switch m {
	case APIDetectionFetch, APIDetectionAxios, APIDetectionXHR,
		APIDetectionWebSocket, APIDetectionGraphQL, APIDetectionSwagger,
		APIDetectionEventSource:
		return true
	default:
		return false
	}
}

// ParseAPIDetectionMethod converts a string to APIDetectionMethod.
func ParseAPIDetectionMethod(s string) APIDetectionMethod {
	switch s {
	case "fetch":
		return APIDetectionFetch
	case "axios":
		return APIDetectionAxios
	case "xhr":
		return APIDetectionXHR
	case "websocket":
		return APIDetectionWebSocket
	case "graphql":
		return APIDetectionGraphQL
	case "swagger":
		return APIDetectionSwagger
	case "eventsource":
		return APIDetectionEventSource
	default:
		return APIDetectionUnknown
	}
}

// CryptoAddressType represents a cryptocurrency address type.
type CryptoAddressType string

// Crypto address type constants.
const (
	// CryptoAddressTypeUnknown represents an unknown address type.
	CryptoAddressTypeUnknown CryptoAddressType = ""

	// Bitcoin address types
	// CryptoAddressTypeBTCLegacy represents legacy Bitcoin addresses (1...).
	CryptoAddressTypeBTCLegacy CryptoAddressType = "btc_legacy"
	// CryptoAddressTypeBTCP2SH represents P2SH Bitcoin addresses (3...).
	CryptoAddressTypeBTCP2SH CryptoAddressType = "btc_p2sh"
	// CryptoAddressTypeBTCBech32 represents Bech32 Bitcoin addresses (bc1q...).
	CryptoAddressTypeBTCBech32 CryptoAddressType = "btc_bech32"
	// CryptoAddressTypeBTCTaproot represents Taproot Bitcoin addresses (bc1p...).
	CryptoAddressTypeBTCTaproot CryptoAddressType = "btc_taproot"

	// Ethereum address types
	// CryptoAddressTypeETH represents Ethereum addresses (0x...).
	CryptoAddressTypeETH CryptoAddressType = "eth"

	// Monero address types
	// CryptoAddressTypeXMRStandard represents standard Monero addresses.
	CryptoAddressTypeXMRStandard CryptoAddressType = "xmr_standard"
	// CryptoAddressTypeXMRIntegrated represents integrated Monero addresses.
	CryptoAddressTypeXMRIntegrated CryptoAddressType = "xmr_integrated"
	// CryptoAddressTypeXMRSubaddress represents Monero subaddresses.
	CryptoAddressTypeXMRSubaddress CryptoAddressType = "xmr_subaddress"

	// Other cryptocurrencies
	// CryptoAddressTypeLTC represents Litecoin addresses.
	CryptoAddressTypeLTC CryptoAddressType = "ltc"
	// CryptoAddressTypeDOGE represents Dogecoin addresses.
	CryptoAddressTypeDOGE CryptoAddressType = "doge"
	// CryptoAddressTypeDASH represents Dash addresses.
	CryptoAddressTypeDASH CryptoAddressType = "dash"
	// CryptoAddressTypeZEC represents Zcash addresses.
	CryptoAddressTypeZEC CryptoAddressType = "zec"
)

// String returns the string representation of the CryptoAddressType.
func (t CryptoAddressType) String() string {
	if t == CryptoAddressTypeUnknown {
		return platformUnknownStr
	}
	return string(t)
}

// IsValid returns true if this is a known address type.
func (t CryptoAddressType) IsValid() bool {
	switch t {
	case CryptoAddressTypeBTCLegacy, CryptoAddressTypeBTCP2SH,
		CryptoAddressTypeBTCBech32, CryptoAddressTypeBTCTaproot,
		CryptoAddressTypeETH, CryptoAddressTypeXMRStandard,
		CryptoAddressTypeXMRIntegrated, CryptoAddressTypeXMRSubaddress,
		CryptoAddressTypeLTC, CryptoAddressTypeDOGE,
		CryptoAddressTypeDASH, CryptoAddressTypeZEC:
		return true
	default:
		return false
	}
}

// Currency returns the cryptocurrency name for this address type.
func (t CryptoAddressType) Currency() string {
	switch t {
	case CryptoAddressTypeBTCLegacy, CryptoAddressTypeBTCP2SH,
		CryptoAddressTypeBTCBech32, CryptoAddressTypeBTCTaproot:
		return "Bitcoin"
	case CryptoAddressTypeETH:
		return "Ethereum"
	case CryptoAddressTypeXMRStandard, CryptoAddressTypeXMRIntegrated,
		CryptoAddressTypeXMRSubaddress:
		return "Monero"
	case CryptoAddressTypeLTC:
		return "Litecoin"
	case CryptoAddressTypeDOGE:
		return "Dogecoin"
	case CryptoAddressTypeDASH:
		return "Dash"
	case CryptoAddressTypeZEC:
		return "Zcash"
	default:
		return "Unknown"
	}
}

// DefaultSeverity returns the default severity for findings of this address type.
func (t CryptoAddressType) DefaultSeverity() Severity {
	switch t {
	case CryptoAddressTypeBTCLegacy, CryptoAddressTypeBTCP2SH,
		CryptoAddressTypeBTCBech32, CryptoAddressTypeBTCTaproot,
		CryptoAddressTypeETH, CryptoAddressTypeLTC, CryptoAddressTypeDOGE,
		CryptoAddressTypeDASH, CryptoAddressTypeZEC:
		// Public blockchain - transactions are traceable
		return SeverityHigh
	case CryptoAddressTypeXMRStandard, CryptoAddressTypeXMRIntegrated,
		CryptoAddressTypeXMRSubaddress:
		// Privacy-focused cryptocurrency
		return SeverityMedium
	default:
		return SeverityHigh
	}
}

// ParseCryptoAddressType converts a string to CryptoAddressType.
// This also handles legacy format strings like "legacy", "bech32", etc.
func ParseCryptoAddressType(s string) CryptoAddressType {
	switch s {
	case "btc_legacy", "legacy":
		return CryptoAddressTypeBTCLegacy
	case "btc_p2sh", "p2sh":
		return CryptoAddressTypeBTCP2SH
	case "btc_bech32", "bech32":
		return CryptoAddressTypeBTCBech32
	case "btc_taproot", "taproot":
		return CryptoAddressTypeBTCTaproot
	case "eth", "ethereum":
		return CryptoAddressTypeETH
	case "xmr_standard", "standard":
		return CryptoAddressTypeXMRStandard
	case "xmr_integrated", "integrated":
		return CryptoAddressTypeXMRIntegrated
	case "xmr_subaddress", "subaddress":
		return CryptoAddressTypeXMRSubaddress
	case "ltc", "litecoin":
		return CryptoAddressTypeLTC
	case "doge", "dogecoin":
		return CryptoAddressTypeDOGE
	case "dash":
		return CryptoAddressTypeDASH
	case "zec", "zcash":
		return CryptoAddressTypeZEC
	default:
		return CryptoAddressTypeUnknown
	}
}

// AWSResourceType represents an AWS resource type.
type AWSResourceType string

// AWS resource type constants.
const (
	// AWSResourceTypeUnknown represents an unknown resource type.
	AWSResourceTypeUnknown AWSResourceType = ""
	// AWSResourceTypeS3 represents S3 buckets.
	AWSResourceTypeS3 AWSResourceType = "s3"
	// AWSResourceTypeCloudFront represents CloudFront distributions.
	AWSResourceTypeCloudFront AWSResourceType = "cloudfront"
	// AWSResourceTypeAPIGateway represents API Gateway endpoints.
	AWSResourceTypeAPIGateway AWSResourceType = "apigateway"
	// AWSResourceTypeLambda represents Lambda functions.
	AWSResourceTypeLambda AWSResourceType = "lambda"
	// AWSResourceTypeEC2 represents EC2 instances.
	AWSResourceTypeEC2 AWSResourceType = "ec2"
)

// String returns the string representation of the AWSResourceType.
func (t AWSResourceType) String() string {
	if t == AWSResourceTypeUnknown {
		return platformUnknownStr
	}
	return string(t)
}

// IsValid returns true if this is a known resource type.
func (t AWSResourceType) IsValid() bool {
	switch t {
	case AWSResourceTypeS3, AWSResourceTypeCloudFront, AWSResourceTypeAPIGateway,
		AWSResourceTypeLambda, AWSResourceTypeEC2:
		return true
	default:
		return false
	}
}

// ParseAWSResourceType converts a string to AWSResourceType.
func ParseAWSResourceType(s string) AWSResourceType {
	switch s {
	case "s3":
		return AWSResourceTypeS3
	case "cloudfront":
		return AWSResourceTypeCloudFront
	case "apigateway":
		return AWSResourceTypeAPIGateway
	case "lambda":
		return AWSResourceTypeLambda
	case "ec2":
		return AWSResourceTypeEC2
	default:
		return AWSResourceTypeUnknown
	}
}
