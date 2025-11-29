package deanon

import (
	"context"
	"strings"

	"github.com/nao1215/onionscan/internal/model"
)

// ServerInfoAnalyzer detects server software and configuration information.
// While not directly identifying, server fingerprints help narrow down
// potential operators and can be correlated with other services.
//
// Design decision: We analyze server info separately because:
//  1. It comes from HTTP headers and protocol scans, not page content
//  2. It's useful for technical fingerprinting
//  3. It can indicate hosting environment and technical sophistication
type ServerInfoAnalyzer struct{}

// NewServerInfoAnalyzer creates a new ServerInfoAnalyzer.
func NewServerInfoAnalyzer() *ServerInfoAnalyzer {
	return &ServerInfoAnalyzer{}
}

// Name returns the analyzer name.
func (a *ServerInfoAnalyzer) Name() string {
	return "serverinfo"
}

// Category returns the analyzer category.
func (a *ServerInfoAnalyzer) Category() string {
	return "technical"
}

// Analyze examines HTTP headers for server information.
func (a *ServerInfoAnalyzer) Analyze(ctx context.Context, data *AnalysisData) ([]model.Finding, error) {
	findings := make([]model.Finding, 0)

	// Analyze pages for header information
	for _, page := range data.Pages {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Server header
		if server := page.GetHeader("Server"); server != "" {
			findings = append(findings, a.analyzeServerHeader(server, page.URL)...)
		}

		// X-Powered-By header
		if poweredBy := page.GetHeader("X-Powered-By"); poweredBy != "" {
			findings = append(findings, model.Finding{
				Type:         "x_powered_by",
				Title:        "X-Powered-By Header Reveals Technology",
				Description:  "The X-Powered-By header reveals the backend technology stack.",
				Severity:     model.SeverityLow,
				SeverityText: model.SeverityLow.String(),
				Value:        poweredBy,
				Location:     page.URL,
			})
		}

		// Via header (proxy information)
		if via := page.GetHeader("Via"); via != "" {
			findings = append(findings, model.Finding{
				Type:         "via_header",
				Title:        "Via Header Present",
				Description:  "The Via header reveals proxy or gateway information.",
				Severity:     model.SeverityLow,
				SeverityText: model.SeverityLow.String(),
				Value:        via,
				Location:     page.URL,
			})
		}

		// X-AspNet-Version
		if aspNet := page.GetHeader("X-AspNet-Version"); aspNet != "" {
			findings = append(findings, model.Finding{
				Type:         "aspnet_version",
				Title:        "ASP.NET Version Disclosed",
				Description:  "The X-AspNet-Version header reveals the .NET framework version.",
				Severity:     model.SeverityLow,
				SeverityText: model.SeverityLow.String(),
				Value:        aspNet,
				Location:     page.URL,
			})
		}
	}

	// Analyze protocol scan results
	if data.ProtocolResults != nil {
		// Check SSH for additional info
		if ssh, ok := data.ProtocolResults["ssh"]; ok && ssh != nil {
			if ssh.Banner != "" {
				findings = append(findings, model.Finding{
					Type:         "ssh_banner",
					Title:        "SSH Banner Information",
					Description:  "The SSH server reveals version and possibly OS information.",
					Severity:     model.SeverityInfo,
					SeverityText: model.SeverityInfo.String(),
					Value:        ssh.Banner,
					Location:     "Port 22",
				})
			}
		}
	}

	return findings, nil
}

// analyzeServerHeader analyzes the Server header for information leaks.
func (a *ServerInfoAnalyzer) analyzeServerHeader(server, url string) []model.Finding {
	findings := make([]model.Finding, 0)
	lower := strings.ToLower(server)

	// Basic version disclosure
	if strings.Contains(server, "/") {
		findings = append(findings, model.Finding{
			Type:         "server_version",
			Title:        "Server Version Disclosed",
			Description:  "The Server header reveals software version information.",
			Severity:     model.SeverityLow,
			SeverityText: model.SeverityLow.String(),
			Value:        server,
			Location:     url,
		})
	}

	// Check for specific servers that reveal more info
	if strings.Contains(lower, "apache") {
		a.analyzeApache(&findings, server, url)
	} else if strings.Contains(lower, "nginx") {
		a.analyzeNginx(&findings, server, url)
	} else if strings.Contains(lower, "microsoft-iis") || strings.Contains(lower, "iis/") {
		a.analyzeIIS(&findings, server, url)
	} else if strings.Contains(lower, "lighttpd") {
		findings = append(findings, model.Finding{
			Type:         "lighttpd_server",
			Title:        "Lighttpd Server Detected",
			Description:  "The server is running lighttpd, commonly used on embedded systems and low-resource environments.",
			Severity:     model.SeverityInfo,
			SeverityText: model.SeverityInfo.String(),
			Value:        server,
			Location:     url,
		})
	}

	return findings
}

// analyzeApache checks for Apache-specific information.
func (a *ServerInfoAnalyzer) analyzeApache(findings *[]model.Finding, server, url string) {
	// Check for OS disclosure in Apache
	osIndicators := map[string]string{
		"ubuntu":  "Ubuntu",
		"debian":  "Debian",
		"centos":  "CentOS",
		"red hat": "Red Hat",
		"fedora":  "Fedora",
		"win32":   "Windows",
		"win64":   "Windows",
	}

	lower := strings.ToLower(server)
	for indicator, osName := range osIndicators {
		if strings.Contains(lower, indicator) {
			*findings = append(*findings, model.Finding{
				Type:         "os_detected",
				Title:        "Operating System Detected from Server Header",
				Description:  "The Apache Server header reveals the operating system.",
				Severity:     model.SeverityLow,
				SeverityText: model.SeverityLow.String(),
				Value:        osName,
				Location:     url,
			})
			break
		}
	}

	// Check for modules (OpenSSL, PHP, etc.)
	if strings.Contains(lower, "openssl") {
		*findings = append(*findings, model.Finding{
			Type:         "openssl_version",
			Title:        "OpenSSL Version Disclosed",
			Description:  "The Server header reveals OpenSSL version information.",
			Severity:     model.SeverityLow,
			SeverityText: model.SeverityLow.String(),
			Value:        server,
			Location:     url,
		})
	}

	if strings.Contains(lower, "php/") {
		*findings = append(*findings, model.Finding{
			Type:         "php_version",
			Title:        "PHP Version Disclosed",
			Description:  "The Server header reveals PHP version information.",
			Severity:     model.SeverityLow,
			SeverityText: model.SeverityLow.String(),
			Value:        server,
			Location:     url,
		})
	}
}

// analyzeNginx checks for Nginx-specific information.
func (a *ServerInfoAnalyzer) analyzeNginx(findings *[]model.Finding, server, url string) {
	// Nginx is often customized, less info typically leaked
	// But version disclosure is still noteworthy
	if strings.Contains(server, "/") {
		*findings = append(*findings, model.Finding{
			Type:         "nginx_version",
			Title:        "Nginx Version Disclosed",
			Description:  "The nginx Server header reveals version information.",
			Severity:     model.SeverityInfo,
			SeverityText: model.SeverityInfo.String(),
			Value:        server,
			Location:     url,
		})
	}
}

// analyzeIIS checks for IIS-specific information.
func (a *ServerInfoAnalyzer) analyzeIIS(findings *[]model.Finding, server, url string) {
	// IIS version reveals Windows version
	iisToWindows := map[string]string{
		"7.0":  "Windows Server 2008/Vista",
		"7.5":  "Windows Server 2008 R2/Windows 7",
		"8.0":  "Windows Server 2012/Windows 8",
		"8.5":  "Windows Server 2012 R2/Windows 8.1",
		"10.0": "Windows Server 2016/2019/Windows 10",
	}

	for iisVer, winVer := range iisToWindows {
		if strings.Contains(server, "IIS/"+iisVer) {
			*findings = append(*findings, model.Finding{
				Type:         "iis_windows_version",
				Title:        "Windows Version Determined from IIS",
				Description:  "The IIS version reveals the Windows version.",
				Severity:     model.SeverityLow,
				SeverityText: model.SeverityLow.String(),
				Value:        winVer + " (IIS " + iisVer + ")",
				Location:     url,
			})
			break
		}
	}
}
