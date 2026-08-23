// Package main provides the controlled Tornago onion fixture used by the E2E suite.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	onionscantor "github.com/nao1215/onionscan/internal/tor"
	"github.com/nao1215/tornago"
)

const testPage = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>OnionScan E2E Service</title>
</head>
<body>
  <h1>OnionScan E2E Service</h1>
  <p>This onion service is owned by the OnionScan test suite.</p>
  <p>Contact: e2e@example.com</p>
  <p>Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa</p>
  <a href="/about">About this service</a>
</body>
</html>`

type siteState struct {
	OnionAddress string `json:"onion_address"`
	OnionURL     string `json:"onion_url"`
	SocksAddress string `json:"socks_address"`
}

func main() {
	statePath := flag.String("state", "", "path to write the ready-state JSON file")
	flag.Parse()

	if *statePath == "" {
		fmt.Fprintln(os.Stderr, "tornago-site: --state is required")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, *statePath); err != nil {
		fmt.Fprintf(os.Stderr, "tornago-site: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, statePath string) error {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen for local HTTP: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "onionscan-e2e/1.0")
		_, _ = fmt.Fprint(w, testPage)
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, "<html><title>About</title><body>Controlled by OnionScan E2E.</body></html>")
	})

	httpServer := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	serverErrors := make(chan error, 1)
	go func() {
		serveErr := httpServer.Serve(listener)
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			serverErrors <- serveErr
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if shutdownErr := httpServer.Shutdown(shutdownCtx); shutdownErr != nil {
			fmt.Fprintf(os.Stderr, "tornago-site: shut down HTTP server: %v\n", shutdownErr)
		}
	}()

	localPort, err := listenerPort(listener)
	if err != nil {
		return err
	}

	launchConfig, err := tornago.NewTorLaunchConfig(
		tornago.WithTorSocksAddr(":0"),
		tornago.WithTorControlAddr(":0"),
		tornago.WithTorStartupTimeout(5*time.Minute),
	)
	if err != nil {
		return fmt.Errorf("configure Tor: %w", err)
	}

	torProcess, err := tornago.StartTorDaemon(launchConfig)
	if err != nil {
		return fmt.Errorf("start Tor: %w", err)
	}
	defer func() { _ = torProcess.Stop() }()

	auth, _, err := tornago.ControlAuthFromTor(torProcess.ControlAddr(), 30*time.Second)
	if err != nil {
		return fmt.Errorf("discover Tor control authentication: %w", err)
	}
	controlClient, err := tornago.NewControlClient(torProcess.ControlAddr(), auth, 30*time.Second)
	if err != nil {
		return fmt.Errorf("create Tor control client: %w", err)
	}
	defer func() { _ = controlClient.Close() }()

	if err := controlClient.Authenticate(); err != nil {
		return fmt.Errorf("authenticate Tor control client: %w", err)
	}

	hiddenServiceConfig, err := tornago.NewHiddenServiceConfig(
		tornago.WithHiddenServiceHTTP(localPort),
	)
	if err != nil {
		return fmt.Errorf("configure hidden service: %w", err)
	}
	hiddenService, err := controlClient.CreateHiddenService(ctx, hiddenServiceConfig)
	if err != nil {
		return fmt.Errorf("create hidden service: %w", err)
	}
	defer func() {
		removeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if removeErr := hiddenService.Remove(removeCtx); removeErr != nil {
			fmt.Fprintf(os.Stderr, "tornago-site: remove hidden service: %v\n", removeErr)
		}
	}()

	state := siteState{
		OnionAddress: hiddenService.OnionAddress(),
		OnionURL:     "http://" + hiddenService.OnionAddress(),
		SocksAddress: torProcess.SocksAddr(),
	}
	if err := waitUntilReachable(ctx, state); err != nil {
		return err
	}
	if err := writeState(statePath, state); err != nil {
		return err
	}

	fmt.Printf("ready onion=%s socks=%s\n", state.OnionAddress, state.SocksAddress)

	select {
	case <-ctx.Done():
		return nil
	case serveErr := <-serverErrors:
		return fmt.Errorf("serve local HTTP: %w", serveErr)
	}
}

func listenerPort(listener net.Listener) (int, error) {
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("unexpected listener address %T", listener.Addr())
	}
	return address.Port, nil
}

func waitUntilReachable(ctx context.Context, state siteState) error {
	client, err := onionscantor.NewClient(state.SocksAddress, 15*time.Second)
	if err != nil {
		return fmt.Errorf("create OnionScan Tor client: %w", err)
	}
	httpClient := client.HTTPClient()
	defer httpClient.CloseIdleConnections()

	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var lastErr error
	for {
		requestCtx, requestCancel := context.WithTimeout(waitCtx, 15*time.Second)
		request, requestErr := http.NewRequestWithContext(requestCtx, http.MethodGet, state.OnionURL, http.NoBody)
		if requestErr == nil {
			response, doErr := httpClient.Do(request)
			if doErr == nil {
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					requestCancel()
					return nil
				}
				lastErr = fmt.Errorf("unexpected HTTP status %s", response.Status)
			} else {
				lastErr = doErr
			}
		} else {
			lastErr = requestErr
		}
		requestCancel()

		select {
		case <-waitCtx.Done():
			if lastErr == nil {
				return fmt.Errorf("hidden service did not become reachable: %w", waitCtx.Err())
			}
			return fmt.Errorf(
				"hidden service did not become reachable: %w",
				errors.Join(waitCtx.Err(), fmt.Errorf("last request: %w", lastErr)),
			)
		case <-ticker.C:
		}
	}
}

func writeState(path string, state siteState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	data = append(data, '\n')

	temporaryPath := path + ".tmp"
	if err := os.WriteFile(temporaryPath, data, 0o600); err != nil {
		return fmt.Errorf("write temporary state: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish state: %w", err)
	}
	return nil
}
