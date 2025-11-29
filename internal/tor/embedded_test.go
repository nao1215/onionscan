package tor

import (
	"testing"
	"time"
)

// TestNewEmbeddedTor tests EmbeddedTor constructor.
func TestNewEmbeddedTor(t *testing.T) {
	t.Parallel()

	t.Run("creates with default timeout", func(t *testing.T) {
		t.Parallel()

		embedded := NewEmbeddedTor()
		if embedded == nil {
			t.Fatal("expected non-nil EmbeddedTor")
		}
		if embedded.startupTimeout != 3*time.Minute {
			t.Errorf("expected default timeout 3m, got %v", embedded.startupTimeout)
		}
	})

	t.Run("applies WithStartupTimeout", func(t *testing.T) {
		t.Parallel()

		embedded := NewEmbeddedTor(WithStartupTimeout(5 * time.Minute))
		if embedded.startupTimeout != 5*time.Minute {
			t.Errorf("expected timeout 5m, got %v", embedded.startupTimeout)
		}
	})
}

// TestEmbeddedTorMethods tests EmbeddedTor methods without starting Tor.
func TestEmbeddedTorMethods(t *testing.T) {
	t.Parallel()

	t.Run("SocksAddr returns empty before start", func(t *testing.T) {
		t.Parallel()

		embedded := NewEmbeddedTor()
		if embedded.SocksAddr() != "" {
			t.Error("expected empty SocksAddr before start")
		}
	})

	t.Run("ControlAddr returns empty before start", func(t *testing.T) {
		t.Parallel()

		embedded := NewEmbeddedTor()
		if embedded.ControlAddr() != "" {
			t.Error("expected empty ControlAddr before start")
		}
	})

	t.Run("IsRunning returns false before start", func(t *testing.T) {
		t.Parallel()

		embedded := NewEmbeddedTor()
		if embedded.IsRunning() {
			t.Error("expected IsRunning to be false before start")
		}
	})

	t.Run("Stop is safe to call on unstarted instance", func(t *testing.T) {
		t.Parallel()

		embedded := NewEmbeddedTor()
		err := embedded.Stop()
		if err != nil {
			t.Errorf("expected no error stopping unstarted instance, got %v", err)
		}
	})

	t.Run("NewClient fails when not running", func(t *testing.T) {
		t.Parallel()

		embedded := NewEmbeddedTor()
		_, err := embedded.NewClient(30 * time.Second)
		if err == nil {
			t.Error("expected error when creating client from unstarted daemon")
		}
	})
}

// TestWithStartupTimeout tests the startup timeout option.
func TestWithStartupTimeout(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		timeout  time.Duration
		expected time.Duration
	}{
		{"1 minute", 1 * time.Minute, 1 * time.Minute},
		{"5 minutes", 5 * time.Minute, 5 * time.Minute},
		{"30 seconds", 30 * time.Second, 30 * time.Second},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			embedded := NewEmbeddedTor(WithStartupTimeout(tc.timeout))
			if embedded.startupTimeout != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, embedded.startupTimeout)
			}
		})
	}
}
