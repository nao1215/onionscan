package deanon

import (
	"context"
	"net/http"
	"testing"

	"github.com/nao1215/onionscan/internal/model"
)

// TestIsAllowedURLHostNormalization pins the fetch policy of the EXIF and
// PDF analyzers for host spellings that name the same host: upper case, a
// trailing dot and an explicit port. Such hosts must be fetched like their
// canonical spelling, and no spelling may ever let a clearnet host through.
func TestIsAllowedURLHostNormalization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		hiddenService string
		url           string
		allowExternal bool
		want          bool
	}{
		// Same origin: always fetched.
		{"target lower case", "target.onion", "http://target.onion/f", false, true},
		{"target upper case", "target.onion", "http://TARGET.ONION/f", false, true},
		{"target mixed case", "target.onion", "http://Target.Onion/f", false, true},
		{"target trailing dot", "target.onion", "http://target.onion./f", false, true},
		{"target with port", "target.onion", "http://target.onion:8080/f", false, true},
		{"target upper case with port and dot", "target.onion", "https://TARGET.ONION.:443/f", false, true},
		{"hidden service given in upper case", "TARGET.ONION", "http://target.onion/f", false, true},
		{"hidden service given with trailing dot", "target.onion.", "http://target.onion/f", false, true},

		// Other onion services: only with external fetch enabled.
		{"other onion blocked by default", "target.onion", "http://other.onion/f", false, false},
		{"other onion upper case blocked by default", "target.onion", "http://OTHER.ONION/f", false, false},
		{"other onion allowed", "target.onion", "http://other.onion/f", true, true},
		{"other onion upper case allowed", "target.onion", "http://OTHER.ONION/f", true, true},
		{"other onion mixed case allowed", "target.onion", "http://Other.Onion/f", true, true},
		{"other onion trailing dot allowed", "target.onion", "http://other.onion./f", true, true},
		{"other onion with port allowed", "target.onion", "http://other.onion:8080/f", true, true},

		// Clearnet: never fetched, whatever the spelling or the setting.
		{"clearnet", "target.onion", "http://example.com/f", true, false},
		{"clearnet upper case", "target.onion", "http://EXAMPLE.COM/f", true, false},
		{"clearnet trailing dot", "target.onion", "http://example.com./f", true, false},
		{"clearnet with port", "target.onion", "http://example.com:8080/f", true, false},
		{"clearnet ipv4", "target.onion", "http://192.168.1.1/f", true, false},
		{"clearnet ipv6", "target.onion", "http://[::1]/f", true, false},
		{"clearnet with onion subdomain", "target.onion", "http://target.onion.example.com/f", true, false},
		{"clearnet with onion in path", "target.onion", "http://example.com/target.onion", true, false},
		{"clearnet with onion userinfo", "target.onion", "http://target.onion@example.com/f", true, false},
		{"clearnet with escaped dot", "target.onion", "http://example%2eonion/f", true, false},
		{"bare onion label", "target.onion", "http://onion./f", true, false},
		{"double trailing dot", "target.onion", "http://other.onion../f", true, false},

		// Unparsable or hostless URLs: never fetched.
		{"invalid url", "target.onion", "http://%/f", true, false},
		{"relative url", "target.onion", "/image.jpg", true, false},
		{"empty host with empty hidden service", "", "http:///f", true, false},
	}

	analyzers := []struct {
		name string
		new  func(hiddenService string, allowExternal bool) func(string) bool
	}{
		{"exif", func(hiddenService string, allowExternal bool) func(string) bool {
			a := NewEXIFAnalyzer()
			a.SetHTTPClient(&http.Client{})
			a.SetAllowExternalFetch(allowExternal)
			_, _ = a.Analyze(context.Background(), &AnalysisData{HiddenService: hiddenService, Pages: []*model.Page{}})
			return a.isAllowedURL
		}},
		{"pdf", func(hiddenService string, allowExternal bool) func(string) bool {
			a := NewPDFAnalyzer()
			a.SetHTTPClient(&http.Client{})
			a.SetAllowExternalFetch(allowExternal)
			_, _ = a.Analyze(context.Background(), &AnalysisData{HiddenService: hiddenService, Pages: []*model.Page{}})
			return a.isAllowedURL
		}},
	}

	for _, an := range analyzers {
		for _, tt := range tests {
			t.Run(an.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()

				isAllowed := an.new(tt.hiddenService, tt.allowExternal)
				if got := isAllowed(tt.url); got != tt.want {
					t.Errorf("isAllowedURL(%q) with hidden service %q and allowExternal=%v = %v, want %v",
						tt.url, tt.hiddenService, tt.allowExternal, got, tt.want)
				}
			})
		}
	}
}
