package deanon

import (
	"net/url"
	"strings"
)

// normalizeHost lower-cases a host name and drops the trailing dot of a fully
// qualified name, so that "TARGET.ONION." and "target.onion" compare equal.
func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// isAllowedFetchURL reports whether an analyzer may fetch rawURL.
//
// URLs on targetHost are always allowed, URLs on other .onion hosts are
// allowed only when allowExternal is true, and everything else (clearnet
// hosts, IP addresses, hostless or unparsable URLs) is refused because
// fetching it could leak the scanner's IP. Host names are compared after
// dropping the port, lower-casing and removing one trailing dot, matching
// how the external link analyzer classifies hosts.
func isAllowedFetchURL(rawURL, targetHost string, allowExternal bool) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	host := normalizeHost(parsed.Hostname())
	if host == "" {
		return false
	}

	if host == normalizeHost(targetHost) {
		return true
	}

	if strings.HasSuffix(host, ".onion") {
		return allowExternal
	}

	return false
}
