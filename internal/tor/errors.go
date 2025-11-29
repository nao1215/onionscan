package tor

import "errors"

// Tor connectivity errors.
// These errors are returned when there are problems connecting to or through Tor.
//
// Design decision: We define specific error types rather than wrapping all errors
// generically. This allows callers to handle different failure modes appropriately
// (e.g., retry on timeout, but fail fast on wrong proxy type).
var (
	// ErrProxyNotTor is returned when the configured proxy address responds
	// but is not a Tor SOCKS5 proxy. This typically happens when connecting
	// to a regular HTTP proxy or a different service on the expected port.
	ErrProxyNotTor = errors.New("proxy is not a Tor SOCKS5 proxy")

	// ErrProxyCannotConnect is returned when we cannot establish a TCP connection
	// to the proxy address. This usually means Tor is not running or the address
	// is incorrect.
	ErrProxyCannotConnect = errors.New("cannot connect to Tor proxy")

	// ErrProxyTimeout is returned when the connection to the proxy times out.
	// This may indicate network issues or an overloaded Tor daemon.
	ErrProxyTimeout = errors.New("timeout connecting to Tor proxy")

	// ErrInvalidProxyAddress is returned when the proxy address format is invalid.
	// Expected format is "host:port".
	ErrInvalidProxyAddress = errors.New("invalid proxy address format: expected host:port")
)

// ProxyStatus represents the result of checking the Tor proxy connection.
// This enum allows for easy status reporting and programmatic handling
// of different proxy states.
type ProxyStatus int

const (
	// ProxyStatusOK indicates the proxy is a working Tor SOCKS5 proxy.
	ProxyStatusOK ProxyStatus = iota

	// ProxyStatusWrongType indicates the proxy is not a Tor proxy.
	// The connection succeeded but the response indicates a different type of proxy.
	ProxyStatusWrongType

	// ProxyStatusCannotConnect indicates we could not establish a connection.
	// Tor may not be running or the address may be wrong.
	ProxyStatusCannotConnect

	// ProxyStatusTimeout indicates the connection attempt timed out.
	// This may be a temporary network issue or an overloaded Tor daemon.
	ProxyStatusTimeout
)

// String returns a human-readable description of the proxy status.
func (s ProxyStatus) String() string {
	switch s {
	case ProxyStatusOK:
		return "OK"
	case ProxyStatusWrongType:
		return "wrong type (not Tor)"
	case ProxyStatusCannotConnect:
		return "cannot connect"
	case ProxyStatusTimeout:
		return "timeout"
	default:
		return "unknown"
	}
}

// Error returns the appropriate error for this status, or nil if OK.
func (s ProxyStatus) Error() error {
	switch s {
	case ProxyStatusOK:
		return nil
	case ProxyStatusWrongType:
		return ErrProxyNotTor
	case ProxyStatusCannotConnect:
		return ErrProxyCannotConnect
	case ProxyStatusTimeout:
		return ErrProxyTimeout
	default:
		return errors.New("unknown proxy status")
	}
}
