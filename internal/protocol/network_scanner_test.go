package protocol

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

type contextDialerFunc struct {
	dialContext func(context.Context, string, string) (net.Conn, error)
}

func (d contextDialerFunc) Dial(network, address string) (net.Conn, error) {
	return d.dialContext(context.Background(), network, address)
}

func (d contextDialerFunc) DialContext(
	ctx context.Context,
	network string,
	address string,
) (net.Conn, error) {
	return d.dialContext(ctx, network, address)
}

func pipeDialer(handler func(net.Conn)) contextDialerFunc {
	return contextDialerFunc{dialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			handler(server)
		}()
		return client, nil
	}}
}

func TestDialProxyWithContext(t *testing.T) {
	t.Parallel()

	t.Run("rejects nil dialer", func(t *testing.T) {
		t.Parallel()

		_, err := dialProxyWithContext(context.Background(), nil, "example.onion:80")
		if !errors.Is(err, errNilDialer) {
			t.Fatalf("expected errNilDialer, got %v", err)
		}
	})

	t.Run("uses context-aware dialer", func(t *testing.T) {
		t.Parallel()

		expectedErr := errors.New("context dialer called")
		var called atomic.Bool
		dialer := contextDialerFunc{dialContext: func(
			ctx context.Context,
			network string,
			address string,
		) (net.Conn, error) {
			called.Store(true)
			if ctx == nil || network != "tcp" || address != "example.onion:80" {
				t.Errorf("unexpected dial arguments: ctx=%v network=%q address=%q", ctx, network, address)
			}
			return nil, expectedErr
		}}

		_, err := dialProxyWithContext(context.Background(), dialer, "example.onion:80")
		if !errors.Is(err, expectedErr) || !called.Load() {
			t.Fatalf("context dialer result was not preserved: called=%v err=%v", called.Load(), err)
		}
	})

	t.Run("returns an already canceled context", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var called atomic.Bool
		dialer := contextDialerFunc{dialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			called.Store(true)
			return nil, nil
		}}

		_, err := dialProxyWithContext(ctx, dialer, "example.onion:80")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation, got %v", err)
		}
		if called.Load() {
			t.Fatal("dialer was called after cancellation")
		}
	})
}

func TestDatabaseScannerConnections(t *testing.T) {
	t.Parallel()

	t.Run("MongoDB connection", func(t *testing.T) {
		t.Parallel()

		scanner := NewMongoDBScanner(pipeDialer(func(net.Conn) {}))
		result, err := scanner.Scan(context.Background(), "mongodb://test.onion/database")
		if err != nil || !result.Detected || len(result.Findings) != 1 {
			t.Fatalf("unexpected MongoDB result: detected=%v findings=%d err=%v", result.Detected, len(result.Findings), err)
		}
	})

	t.Run("PostgreSQL connection", func(t *testing.T) {
		t.Parallel()

		scanner := NewPostgreSQLScanner(pipeDialer(func(net.Conn) {}))
		result, err := scanner.Scan(context.Background(), "postgres://test.onion/database")
		if err != nil || !result.Detected || len(result.Findings) != 1 {
			t.Fatalf("unexpected PostgreSQL result: detected=%v findings=%d err=%v", result.Detected, len(result.Findings), err)
		}
	})

	for _, response := range []string{"+PONG\r\n", "-NOAUTH Authentication required\r\n"} {
		t.Run("Redis "+strings.Fields(response)[0], func(t *testing.T) {
			t.Parallel()

			scanner := NewRedisScanner(pipeDialer(func(conn net.Conn) {
				request := make([]byte, len("PING\r\n"))
				_, _ = io.ReadFull(conn, request)
				_, _ = io.WriteString(conn, response)
			}))
			result, err := scanner.Scan(context.Background(), "redis://test.onion")
			if err != nil || !result.Detected || result.Banner == "" || len(result.Findings) != 1 {
				t.Fatalf("unexpected Redis result: detected=%v banner=%q findings=%d err=%v", result.Detected, result.Banner, len(result.Findings), err)
			}
		})
	}

	for _, version := range []string{"8.4.0", "11.4.2-MariaDB"} {
		t.Run("MySQL "+version, func(t *testing.T) {
			t.Parallel()

			scanner := NewMySQLScanner(pipeDialer(func(conn net.Conn) {
				greeting := append([]byte{0x10, 0x00, 0x00, 0x00, 0x0a}, []byte(version)...)
				greeting = append(greeting, 0)
				_, _ = conn.Write(greeting)
			}))
			result, err := scanner.Scan(context.Background(), "mysql://test.onion")
			if err != nil || !result.Detected || result.Banner != version || len(result.Findings) != 1 {
				t.Fatalf("unexpected MySQL result: detected=%v banner=%q findings=%d err=%v", result.Detected, result.Banner, len(result.Findings), err)
			}
			expectedType := "MySQL"
			if strings.Contains(version, "MariaDB") {
				expectedType = "MariaDB"
			}
			if result.GetMetadata("database_type") != expectedType {
				t.Fatalf("database_type = %v, want %q", result.GetMetadata("database_type"), expectedType)
			}
		})
	}
}

func TestBannerScannerConnections(t *testing.T) {
	t.Parallel()

	t.Run("SSH", func(t *testing.T) {
		t.Parallel()

		scanner := NewSSHScanner(pipeDialer(func(conn net.Conn) {
			_, _ = io.WriteString(conn, "SSH-2.0-OpenSSH_6.6 Ubuntu\r\n")
		}))
		result, err := scanner.Scan(context.Background(), "ssh://test.onion/path")
		if err != nil || !result.Detected || result.Banner == "" || len(result.Findings) < 3 {
			t.Fatalf("unexpected SSH result: detected=%v banner=%q findings=%d err=%v", result.Detected, result.Banner, len(result.Findings), err)
		}
	})

	t.Run("FTP multiline banner", func(t *testing.T) {
		t.Parallel()

		scanner := NewFTPScanner(pipeDialer(func(conn net.Conn) {
			_, _ = io.WriteString(conn, "220-Welcome to server.example.com/vsftpd\r\n220 Ready\r\n")
		}))
		result, err := scanner.Scan(context.Background(), "ftp://test.onion/path")
		if err != nil || !result.Detected || !strings.Contains(result.Banner, "220 Ready") || len(result.Findings) < 3 {
			t.Fatalf("unexpected FTP result: detected=%v banner=%q findings=%d err=%v", result.Detected, result.Banner, len(result.Findings), err)
		}
	})

	t.Run("SMTP multiline banner", func(t *testing.T) {
		t.Parallel()

		scanner := NewSMTPScanner(pipeDialer(func(conn net.Conn) {
			_, _ = io.WriteString(conn, "220-mail.example.com ESMTP Postfix\r\n220 Ready\r\n")
		}))
		result, err := scanner.Scan(context.Background(), "smtp://test.onion/path")
		if err != nil || !result.Detected || !strings.Contains(result.Banner, "220 Ready") || len(result.Findings) < 2 {
			t.Fatalf("unexpected SMTP result: detected=%v banner=%q findings=%d err=%v", result.Detected, result.Banner, len(result.Findings), err)
		}
	})
}
