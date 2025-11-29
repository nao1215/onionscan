package tor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nao1215/tornago"
)

// EmbeddedTor manages an embedded Tor daemon using tornago.
// It provides automatic startup and shutdown of the Tor process,
// eliminating the need for an external Tor installation.
//
// Design decision: We use tornago's embedded Tor functionality because:
//  1. It simplifies deployment - no external Tor daemon required
//  2. It provides better control over the Tor process lifecycle
//  3. It allows OnionScan to work "out of the box" without setup
//
// Note: Starting the embedded Tor daemon takes 1-3 minutes as it needs to:
//   - Download directory information from the Tor network
//   - Build initial circuits through the relay network
//   - Establish SOCKS and control port listeners
type EmbeddedTor struct {
	// process is the running Tor daemon process.
	process *tornago.TorProcess

	// socksAddr is the SOCKS5 proxy address (set after successful startup).
	socksAddr string

	// controlAddr is the control port address (set after successful startup).
	controlAddr string

	// startupTimeout is the maximum time to wait for Tor to bootstrap.
	startupTimeout time.Duration
}

// EmbeddedTorOption configures an EmbeddedTor instance.
type EmbeddedTorOption func(*EmbeddedTor)

// WithStartupTimeout sets the maximum time to wait for Tor to bootstrap.
func WithStartupTimeout(timeout time.Duration) EmbeddedTorOption {
	return func(e *EmbeddedTor) {
		e.startupTimeout = timeout
	}
}

// NewEmbeddedTor creates a new embedded Tor manager.
// Call Start() to actually launch the Tor daemon.
func NewEmbeddedTor(opts ...EmbeddedTorOption) *EmbeddedTor {
	e := &EmbeddedTor{
		startupTimeout: 3 * time.Minute, // Default timeout
	}

	for _, opt := range opts {
		opt(e)
	}

	return e
}

// Start launches the embedded Tor daemon and waits for it to bootstrap.
// This typically takes 1-3 minutes depending on network conditions.
//
// The context can be used to cancel the startup if needed.
// Returns an error if Tor fails to start within the timeout period.
func (e *EmbeddedTor) Start(ctx context.Context) error {
	// Create launch configuration with random ports
	// Using ":0" lets the OS assign available ports automatically
	launchCfg, err := tornago.NewTorLaunchConfig(
		tornago.WithTorSocksAddr(":0"),
		tornago.WithTorControlAddr(":0"),
		tornago.WithTorStartupTimeout(e.startupTimeout),
	)
	if err != nil {
		return fmt.Errorf("failed to create Tor launch config: %w", err)
	}

	// Start the Tor daemon
	// This call blocks until Tor is fully bootstrapped or times out
	process, err := tornago.StartTorDaemon(launchCfg)
	if err != nil {
		return fmt.Errorf("failed to start embedded Tor daemon: %w", err)
	}

	// Check if context was cancelled during startup
	select {
	case <-ctx.Done():
		// Clean up the started process
		_ = process.Stop() //nolint:errcheck // Best effort cleanup
		return ctx.Err()
	default:
		// Continue
	}

	e.process = process
	e.socksAddr = process.SocksAddr()
	e.controlAddr = process.ControlAddr()

	return nil
}

// Stop gracefully shuts down the embedded Tor daemon.
// This should be called when the application exits to clean up resources.
//
// It's safe to call Stop() multiple times or on an unstarted instance.
func (e *EmbeddedTor) Stop() error {
	if e.process == nil {
		return nil
	}

	err := e.process.Stop()
	e.process = nil
	return err
}

// SocksAddr returns the SOCKS5 proxy address of the running Tor daemon.
// Returns an empty string if Tor is not running.
//
// The format is "host:port" (e.g., "127.0.0.1:42715").
// This address can be passed to NewClient() to create a Tor client.
func (e *EmbeddedTor) SocksAddr() string {
	return e.socksAddr
}

// ControlAddr returns the control port address of the running Tor daemon.
// Returns an empty string if Tor is not running.
//
// The control port can be used for advanced Tor control operations,
// but is not required for basic scanning functionality.
func (e *EmbeddedTor) ControlAddr() string {
	return e.controlAddr
}

// IsRunning returns true if the embedded Tor daemon is currently running.
func (e *EmbeddedTor) IsRunning() bool {
	return e.process != nil
}

// NewClient creates a new Tor client using the embedded daemon's SOCKS proxy.
// Returns an error if the embedded Tor daemon is not running.
func (e *EmbeddedTor) NewClient(timeout time.Duration) (*Client, error) {
	if !e.IsRunning() {
		return nil, errors.New("embedded Tor daemon is not running")
	}

	return NewClient(e.socksAddr, timeout)
}
