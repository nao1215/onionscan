package pipeline

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nao1215/onionscan/internal/model"
)

// TestBatchProcessorNew tests the BatchProcessor constructor.
func TestBatchProcessorNew(t *testing.T) {
	t.Parallel()

	t.Run("creates processor with defaults", func(t *testing.T) {
		t.Parallel()

		bp := NewBatchProcessor(func() *Pipeline { return New() })

		if bp == nil {
			t.Fatal("expected non-nil processor")
		}
		if bp.concurrency != 10 {
			t.Errorf("expected default concurrency 10, got %d", bp.concurrency)
		}
	})

	t.Run("applies WithConcurrency option", func(t *testing.T) {
		t.Parallel()

		bp := NewBatchProcessor(
			func() *Pipeline { return New() },
			WithConcurrency(5),
		)

		if bp.concurrency != 5 {
			t.Errorf("expected concurrency 5, got %d", bp.concurrency)
		}
	})

	t.Run("ignores non-positive concurrency", func(t *testing.T) {
		t.Parallel()

		bp := NewBatchProcessor(
			func() *Pipeline { return New() },
			WithConcurrency(0),
		)

		if bp.concurrency != 10 { // Should keep default
			t.Errorf("expected concurrency 10, got %d", bp.concurrency)
		}
	})

	t.Run("applies WithBatchLogger option", func(t *testing.T) {
		t.Parallel()

		bp := NewBatchProcessor(
			func() *Pipeline { return New() },
			WithBatchLogger(nil),
		)

		// When WithBatchLogger(nil) is passed, the logger should be set to default
		if bp == nil {
			t.Fatal("expected non-nil processor")
		}
		if bp.logger == nil {
			t.Error("expected non-nil logger")
		}
	})
}

// TestBatchProcessorProcessBatch tests batch processing.
func TestBatchProcessorProcessBatch(t *testing.T) {
	t.Parallel()

	t.Run("processes all services", func(t *testing.T) {
		t.Parallel()

		var processedCount atomic.Int32

		bp := NewBatchProcessor(func() *Pipeline {
			p := New()
			p.AddStep(&mockStep{
				name: "counter",
				doFunc: func(_ context.Context, _ *model.OnionScanReport) error {
					processedCount.Add(1)
					return nil
				},
			})
			return p
		})

		services := []string{
			"service1.onion",
			"service2.onion",
			"service3.onion",
		}

		results, err := bp.ProcessBatch(context.Background(), services)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) != 3 {
			t.Errorf("expected 3 results, got %d", len(results))
		}
		if processedCount.Load() != 3 {
			t.Errorf("expected 3 processed, got %d", processedCount.Load())
		}
	})

	t.Run("respects concurrency limit", func(t *testing.T) {
		t.Parallel()

		var maxConcurrent atomic.Int32
		var currentConcurrent atomic.Int32
		var mu sync.Mutex

		bp := NewBatchProcessor(
			func() *Pipeline {
				p := New()
				p.AddStep(&mockStep{
					name: "concurrent-counter",
					doFunc: func(_ context.Context, _ *model.OnionScanReport) error {
						current := currentConcurrent.Add(1)

						// Update max if needed (with mutex for safety)
						mu.Lock()
						if current > maxConcurrent.Load() {
							maxConcurrent.Store(current)
						}
						mu.Unlock()

						// Simulate some work
						time.Sleep(50 * time.Millisecond)

						currentConcurrent.Add(-1)
						return nil
					},
				})
				return p
			},
			WithConcurrency(2),
		)

		services := make([]string, 10)
		for i := range services {
			services[i] = "service.onion"
		}

		_, err := bp.ProcessBatch(context.Background(), services)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if maxConcurrent.Load() > 2 {
			t.Errorf("max concurrent was %d, expected <= 2", maxConcurrent.Load())
		}
	})

	t.Run("maintains result order", func(t *testing.T) {
		t.Parallel()

		bp := NewBatchProcessor(func() *Pipeline {
			p := New()
			p.AddStep(&mockStep{name: "noop"})
			return p
		})

		services := []string{
			"first.onion",
			"second.onion",
			"third.onion",
		}

		results, err := bp.ProcessBatch(context.Background(), services)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for i, result := range results {
			if result.HiddenService != services[i] {
				t.Errorf("result[%d]: got %q, expected %q",
					i, result.HiddenService, services[i])
			}
		}
	})

	t.Run("continues after individual scan failure", func(t *testing.T) {
		t.Parallel()

		var processedCount atomic.Int32

		bp := NewBatchProcessor(func() *Pipeline {
			p := New()
			p.AddStep(&mockStep{
				name: "sometimes-fails",
				doFunc: func(_ context.Context, report *model.OnionScanReport) error {
					processedCount.Add(1)
					// Fail for the second service only
					if report.HiddenService == "fail.onion" {
						return errors.New("simulated scan failure")
					}
					return nil
				},
			})
			return p
		})

		services := []string{
			"first.onion",
			"fail.onion",
			"third.onion",
		}

		results, err := bp.ProcessBatch(context.Background(), services)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if processedCount.Load() != 3 {
			t.Errorf("expected 3 processed, got %d", processedCount.Load())
		}
		// Check that the failed scan has an error recorded
		if results[1].Error == nil {
			t.Error("expected error in second result")
		}
	})

	t.Run("handles context cancellation", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())

		var startedCount atomic.Int32

		bp := NewBatchProcessor(
			func() *Pipeline {
				p := New()
				p.AddStep(&mockStep{
					name: "slow-step",
					doFunc: func(ctx context.Context, _ *model.OnionScanReport) error {
						startedCount.Add(1)
						select {
						case <-ctx.Done():
							return ctx.Err()
						case <-time.After(time.Second):
							return nil
						}
					},
				})
				return p
			},
			WithConcurrency(2),
		)

		services := make([]string, 10)
		for i := range services {
			services[i] = "service.onion"
		}

		// Cancel after a short delay
		go func() {
			time.Sleep(100 * time.Millisecond)
			cancel()
		}()

		_, err := bp.ProcessBatch(ctx, services)

		// Should return context.Canceled
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
		// Not all services should have started
		//nolint:gosec // len(services) is small, no overflow risk
		if startedCount.Load() >= int32(len(services)) {
			t.Error("expected some services to not start due to cancellation")
		}
	})
}

// TestBatchProcessorProcessBatchWithCallback tests callback-based processing.
func TestBatchProcessorProcessBatchWithCallback(t *testing.T) {
	t.Parallel()

	t.Run("calls callback for each result", func(t *testing.T) {
		t.Parallel()

		var callbackCount atomic.Int32
		var mu sync.Mutex
		receivedServices := make(map[string]bool)

		bp := NewBatchProcessor(func() *Pipeline {
			p := New()
			p.AddStep(&mockStep{name: "noop"})
			return p
		})

		services := []string{
			"first.onion",
			"second.onion",
			"third.onion",
		}

		err := bp.ProcessBatchWithCallback(
			context.Background(),
			services,
			func(report *model.OnionScanReport, _ int) {
				callbackCount.Add(1)
				mu.Lock()
				receivedServices[report.HiddenService] = true
				mu.Unlock()
			},
		)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if callbackCount.Load() != 3 {
			t.Errorf("expected 3 callbacks, got %d", callbackCount.Load())
		}
		for _, service := range services {
			if !receivedServices[service] {
				t.Errorf("missing callback for %q", service)
			}
		}
	})
}
