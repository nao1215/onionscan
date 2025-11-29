package deanon

import (
	"context"
	"regexp"
	"strings"

	"github.com/nao1215/onionscan/internal/model"
)

// categoryAttack is the analyzer category for attack detection.
const categoryAttack = "attack"

// FingerprintAnalyzer detects browser fingerprinting techniques in page content.
// These techniques can uniquely identify visitors even without cookies.
//
// This analyzer checks for:
//   - Canvas fingerprinting
//   - WebGL fingerprinting
//   - AudioContext fingerprinting
//   - WebRTC IP leaks
type FingerprintAnalyzer struct {
	// patterns for detecting fingerprinting code
	patterns map[string]*fingerprintPattern
}

type fingerprintPattern struct {
	regex       *regexp.Regexp
	title       string
	description string
	severity    model.Severity
}

// NewFingerprintAnalyzer creates a new FingerprintAnalyzer.
func NewFingerprintAnalyzer() *FingerprintAnalyzer {
	return &FingerprintAnalyzer{
		patterns: map[string]*fingerprintPattern{
			// Canvas fingerprinting
			"canvas_toDataURL": {
				regex:       regexp.MustCompile(`\.toDataURL\s*\(`),
				title:       "Canvas Fingerprinting Detected",
				description: "Canvas toDataURL() was found, commonly used for browser fingerprinting. This can uniquely identify visitors without cookies.",
				severity:    model.SeverityHigh,
			},
			"canvas_getImageData": {
				regex:       regexp.MustCompile(`\.getImageData\s*\(`),
				title:       "Canvas Fingerprinting Detected",
				description: "Canvas getImageData() was found, commonly used for browser fingerprinting to extract pixel data.",
				severity:    model.SeverityHigh,
			},

			// WebGL fingerprinting
			"webgl_getParameter": {
				regex:       regexp.MustCompile(`getParameter\s*\(\s*(gl\.|WebGL)`),
				title:       "WebGL Fingerprinting Detected",
				description: "WebGL getParameter() calls were found, often used to fingerprint GPU and driver information.",
				severity:    model.SeverityHigh,
			},
			"webgl_renderer": {
				regex:       regexp.MustCompile(`UNMASKED_(VENDOR|RENDERER)_WEBGL`),
				title:       "WebGL Renderer Fingerprinting",
				description: "WebGL renderer/vendor query detected. This extracts GPU information for fingerprinting.",
				severity:    model.SeverityHigh,
			},

			// AudioContext fingerprinting
			"audio_fingerprint": {
				regex:       regexp.MustCompile(`(AudioContext|webkitAudioContext)\s*\(`),
				title:       "AudioContext Fingerprinting Risk",
				description: "AudioContext API usage detected. This can be used to fingerprint audio hardware.",
				severity:    model.SeverityMedium,
			},
			"audio_oscillator": {
				regex:       regexp.MustCompile(`createOscillator\s*\(`),
				title:       "Audio Oscillator Fingerprinting",
				description: "Audio oscillator creation detected, commonly used in AudioContext fingerprinting techniques.",
				severity:    model.SeverityMedium,
			},

			// WebRTC IP leak
			"webrtc_peer": {
				regex:       regexp.MustCompile(`RTCPeerConnection\s*\(`),
				title:       "WebRTC IP Leak Risk",
				description: "RTCPeerConnection detected. WebRTC can leak real IP addresses even when using Tor.",
				severity:    model.SeverityCritical,
			},
			"webrtc_datachannel": {
				regex:       regexp.MustCompile(`createDataChannel\s*\(`),
				title:       "WebRTC DataChannel Detected",
				description: "WebRTC DataChannel usage detected, which can leak real IP addresses.",
				severity:    model.SeverityHigh,
			},
			"webrtc_stun": {
				regex:       regexp.MustCompile(`stun:|turn:`),
				title:       "STUN/TURN Server Reference",
				description: "STUN/TURN server reference found. These are used by WebRTC and can leak IP addresses.",
				severity:    model.SeverityHigh,
			},

			// Navigator fingerprinting
			"navigator_plugins": {
				regex:       regexp.MustCompile(`navigator\.(plugins|mimeTypes)`),
				title:       "Plugin Enumeration Detected",
				description: "Navigator plugins/mimeTypes enumeration detected, used for browser fingerprinting.",
				severity:    model.SeverityMedium,
			},

			// Font fingerprinting
			"font_detection": {
				regex:       regexp.MustCompile(`(measureText|font-family.*,.*,|detectFont)`),
				title:       "Font Detection Fingerprinting",
				description: "Font detection techniques found that could be used for browser fingerprinting.",
				severity:    model.SeverityMedium,
			},
		},
	}
}

// Name returns the analyzer name.
func (a *FingerprintAnalyzer) Name() string {
	return "fingerprint"
}

// Category returns the analyzer category.
func (a *FingerprintAnalyzer) Category() string {
	return categoryAttack
}

// Analyze searches for fingerprinting code in page content.
func (a *FingerprintAnalyzer) Analyze(ctx context.Context, data *AnalysisData) ([]model.Finding, error) {
	findings := make([]model.Finding, 0)
	seenPatterns := make(map[string]bool)

	for _, page := range data.Pages {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Use the page snapshot which includes all text content
		content := page.Snapshot

		for patternName, pattern := range a.patterns {
			// Check if pattern matches
			if !pattern.regex.MatchString(content) {
				continue
			}

			// Only report each pattern type once per scan
			key := patternName + ":" + page.URL
			if seenPatterns[key] {
				continue
			}
			seenPatterns[key] = true

			findings = append(findings, model.Finding{
				Type:         "fingerprint_" + patternName,
				Title:        pattern.title,
				Description:  pattern.description,
				Severity:     pattern.severity,
				SeverityText: pattern.severity.String(),
				Value:        patternName,
				Location:     page.URL,
			})
		}

		// Check for combined fingerprinting (multiple techniques)
		findings = append(findings, a.checkCombinedFingerprinting(page, content)...)
	}

	return findings, nil
}

// checkCombinedFingerprinting detects when multiple fingerprinting
// techniques are used together, which indicates intentional tracking.
func (a *FingerprintAnalyzer) checkCombinedFingerprinting(page *model.Page, content string) []model.Finding {
	findings := make([]model.Finding, 0)

	count := 0
	techniques := make([]string, 0)

	// Check for canvas
	if strings.Contains(content, "toDataURL") || strings.Contains(content, "getImageData") {
		count++
		techniques = append(techniques, "Canvas")
	}

	// Check for WebGL
	if strings.Contains(content, "UNMASKED") || strings.Contains(content, "getParameter") {
		count++
		techniques = append(techniques, "WebGL")
	}

	// Check for AudioContext
	if strings.Contains(content, "AudioContext") || strings.Contains(content, "createOscillator") {
		count++
		techniques = append(techniques, "AudioContext")
	}

	// Check for WebRTC
	if strings.Contains(content, "RTCPeerConnection") {
		count++
		techniques = append(techniques, "WebRTC")
	}

	// If 3 or more techniques found, this is likely deliberate fingerprinting
	if count >= 3 {
		findings = append(findings, model.Finding{
			Type:         "fingerprint_combined",
			Title:        "Multiple Fingerprinting Techniques Detected",
			Description:  "Multiple browser fingerprinting techniques are used together, indicating intentional visitor tracking.",
			Severity:     model.SeverityCritical,
			SeverityText: model.SeverityCritical.String(),
			Value:        strings.Join(techniques, ", "),
			Location:     page.URL,
		})
	}

	return findings
}
