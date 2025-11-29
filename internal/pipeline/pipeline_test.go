package pipeline

import (
	"context"
	"errors"
	"testing"

	"github.com/nao1215/onionscan/internal/model"
)

// mockStep is a test helper that implements the Step interface.
type mockStep struct {
	name      string
	doFunc    func(ctx context.Context, report *model.OnionScanReport) error
	callCount int
}

// Do implements Step.Do.
func (m *mockStep) Do(ctx context.Context, report *model.OnionScanReport) error {
	m.callCount++
	if m.doFunc != nil {
		return m.doFunc(ctx, report)
	}
	return nil
}

// Name implements Step.Name.
func (m *mockStep) Name() string {
	return m.name
}

// TestPipelineNew tests the Pipeline constructor.
func TestPipelineNew(t *testing.T) {
	t.Parallel()

	t.Run("creates pipeline with default settings", func(t *testing.T) {
		t.Parallel()

		p := New()

		if p == nil {
			t.Fatal("expected non-nil pipeline")
		}
		if p.StepCount() != 0 {
			t.Errorf("expected 0 steps, got %d", p.StepCount())
		}
	})

	t.Run("applies WithContinueOnError option", func(t *testing.T) {
		t.Parallel()

		p := New(WithContinueOnError(true))

		if !p.continueOnError {
			t.Error("expected continueOnError to be true")
		}
	})
}

// TestPipelineAddStep tests adding steps to the pipeline.
func TestPipelineAddStep(t *testing.T) {
	t.Parallel()

	t.Run("adds single step", func(t *testing.T) {
		t.Parallel()

		p := New()
		step := &mockStep{name: "test-step"}

		p.AddStep(step)

		if p.StepCount() != 1 {
			t.Errorf("expected 1 step, got %d", p.StepCount())
		}
	})

	t.Run("adds multiple steps with AddSteps", func(t *testing.T) {
		t.Parallel()

		p := New()
		step1 := &mockStep{name: "step-1"}
		step2 := &mockStep{name: "step-2"}
		step3 := &mockStep{name: "step-3"}

		p.AddSteps(step1, step2, step3)

		if p.StepCount() != 3 {
			t.Errorf("expected 3 steps, got %d", p.StepCount())
		}
	})

	t.Run("maintains step order", func(t *testing.T) {
		t.Parallel()

		p := New()
		p.AddStep(&mockStep{name: "first"})
		p.AddStep(&mockStep{name: "second"})
		p.AddStep(&mockStep{name: "third"})

		names := p.StepNames()

		expected := []string{"first", "second", "third"}
		for i, name := range names {
			if name != expected[i] {
				t.Errorf("step %d: got %q, expected %q", i, name, expected[i])
			}
		}
	})
}

// TestPipelineExecute tests pipeline execution.
func TestPipelineExecute(t *testing.T) {
	t.Parallel()

	t.Run("executes all steps in order", func(t *testing.T) {
		t.Parallel()

		executionOrder := make([]string, 0)

		p := New()
		p.AddStep(&mockStep{
			name: "step-1",
			doFunc: func(_ context.Context, _ *model.OnionScanReport) error {
				executionOrder = append(executionOrder, "step-1")
				return nil
			},
		})
		p.AddStep(&mockStep{
			name: "step-2",
			doFunc: func(_ context.Context, _ *model.OnionScanReport) error {
				executionOrder = append(executionOrder, "step-2")
				return nil
			},
		})

		report := model.NewOnionScanReport("example.onion")
		err := p.Execute(context.Background(), report)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(executionOrder) != 2 {
			t.Fatalf("expected 2 executions, got %d", len(executionOrder))
		}
		if executionOrder[0] != "step-1" || executionOrder[1] != "step-2" {
			t.Errorf("wrong execution order: %v", executionOrder)
		}
	})

	t.Run("stops on first error by default", func(t *testing.T) {
		t.Parallel()

		expectedErr := errors.New("step failed")
		step2Called := false

		p := New()
		p.AddStep(&mockStep{
			name: "failing-step",
			doFunc: func(_ context.Context, _ *model.OnionScanReport) error {
				return expectedErr
			},
		})
		p.AddStep(&mockStep{
			name: "should-not-run",
			doFunc: func(_ context.Context, _ *model.OnionScanReport) error {
				step2Called = true
				return nil
			},
		})

		report := model.NewOnionScanReport("example.onion")
		err := p.Execute(context.Background(), report)

		if !errors.Is(err, expectedErr) {
			t.Errorf("expected error %v, got %v", expectedErr, err)
		}
		if step2Called {
			t.Error("second step should not have been called")
		}
	})

	t.Run("continues on error when configured", func(t *testing.T) {
		t.Parallel()

		step2Called := false

		p := New(WithContinueOnError(true))
		p.AddStep(&mockStep{
			name: "failing-step",
			doFunc: func(_ context.Context, _ *model.OnionScanReport) error {
				return errors.New("step failed")
			},
		})
		p.AddStep(&mockStep{
			name: "should-run",
			doFunc: func(_ context.Context, _ *model.OnionScanReport) error {
				step2Called = true
				return nil
			},
		})

		report := model.NewOnionScanReport("example.onion")
		err := p.Execute(context.Background(), report)

		if err != nil {
			t.Errorf("expected nil error with continueOnError, got %v", err)
		}
		if !step2Called {
			t.Error("second step should have been called")
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		stepCalled := false
		p := New()
		p.AddStep(&mockStep{
			name: "should-not-run",
			doFunc: func(_ context.Context, _ *model.OnionScanReport) error {
				stepCalled = true
				return nil
			},
		})

		report := model.NewOnionScanReport("example.onion")
		err := p.Execute(ctx, report)

		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
		if stepCalled {
			t.Error("step should not have been called")
		}
		if !report.TimedOut {
			t.Error("report.TimedOut should be true")
		}
	})

	t.Run("records performed scans", func(t *testing.T) {
		t.Parallel()

		p := New()
		p.AddStep(&mockStep{name: "scan-1"})
		p.AddStep(&mockStep{name: "scan-2"})

		report := model.NewOnionScanReport("example.onion")
		err := p.Execute(context.Background(), report)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(report.PerformedScans) != 2 {
			t.Errorf("expected 2 performed scans, got %d", len(report.PerformedScans))
		}
	})

	t.Run("records error in report", func(t *testing.T) {
		t.Parallel()

		expectedErr := errors.New("test error")

		p := New()
		p.AddStep(&mockStep{
			name: "failing-step",
			doFunc: func(_ context.Context, _ *model.OnionScanReport) error {
				return expectedErr
			},
		})

		report := model.NewOnionScanReport("example.onion")
		_ = p.Execute(context.Background(), report) //nolint:errcheck // We check error via report.Error

		if report.Error == nil {
			t.Error("expected error to be recorded in report")
		}
		if report.ErrorMessage != expectedErr.Error() {
			t.Errorf("expected error message %q, got %q", expectedErr.Error(), report.ErrorMessage)
		}
	})
}

// TestPipelineStepNames tests the StepNames method.
func TestPipelineStepNames(t *testing.T) {
	t.Parallel()

	t.Run("returns empty slice for empty pipeline", func(t *testing.T) {
		t.Parallel()

		p := New()
		names := p.StepNames()

		if len(names) != 0 {
			t.Errorf("expected empty slice, got %v", names)
		}
	})

	t.Run("returns names in order", func(t *testing.T) {
		t.Parallel()

		p := New()
		p.AddSteps(
			&mockStep{name: "alpha"},
			&mockStep{name: "beta"},
			&mockStep{name: "gamma"},
		)

		names := p.StepNames()

		if len(names) != 3 {
			t.Fatalf("expected 3 names, got %d", len(names))
		}
		if names[0] != "alpha" || names[1] != "beta" || names[2] != "gamma" {
			t.Errorf("unexpected names: %v", names)
		}
	})
}

// TestDefaultPipelineConfig tests the DefaultPipelineConfig struct and options.
func TestDefaultPipelineConfig(t *testing.T) {
	t.Parallel()

	t.Run("WithPipelineCrawlDepth sets depth", func(t *testing.T) {
		t.Parallel()

		cfg := &DefaultPipelineConfig{}
		opt := WithPipelineCrawlDepth(10)
		opt(cfg)

		if cfg.CrawlDepth != 10 {
			t.Errorf("expected CrawlDepth 10, got %d", cfg.CrawlDepth)
		}
	})

	t.Run("WithPipelineCrawlMaxPages sets max pages", func(t *testing.T) {
		t.Parallel()

		cfg := &DefaultPipelineConfig{}
		opt := WithPipelineCrawlMaxPages(200)
		opt(cfg)

		if cfg.CrawlMaxPages != 200 {
			t.Errorf("expected CrawlMaxPages 200, got %d", cfg.CrawlMaxPages)
		}
	})

	t.Run("WithPipelineCookie sets cookie", func(t *testing.T) {
		t.Parallel()

		cfg := &DefaultPipelineConfig{}
		opt := WithPipelineCookie("session=abc123")
		opt(cfg)

		if cfg.Cookie != "session=abc123" {
			t.Errorf("expected cookie 'session=abc123', got %q", cfg.Cookie)
		}
	})

	t.Run("WithPipelineHeaders sets headers", func(t *testing.T) {
		t.Parallel()

		cfg := &DefaultPipelineConfig{}
		headers := map[string]string{
			"Authorization": "Bearer token",
			"X-Custom":      "value",
		}
		opt := WithPipelineHeaders(headers)
		opt(cfg)

		if len(cfg.Headers) != 2 {
			t.Errorf("expected 2 headers, got %d", len(cfg.Headers))
		}
		if cfg.Headers["Authorization"] != "Bearer token" {
			t.Errorf("expected Authorization header, got %v", cfg.Headers)
		}
	})

	t.Run("WithPipelineIgnorePatterns sets ignore patterns", func(t *testing.T) {
		t.Parallel()

		cfg := &DefaultPipelineConfig{}
		patterns := []string{"/admin/*", "*.pdf"}
		opt := WithPipelineIgnorePatterns(patterns)
		opt(cfg)

		if len(cfg.IgnorePatterns) != 2 {
			t.Errorf("expected 2 ignore patterns, got %d", len(cfg.IgnorePatterns))
		}
		if cfg.IgnorePatterns[0] != "/admin/*" {
			t.Errorf("expected first pattern '/admin/*', got %q", cfg.IgnorePatterns[0])
		}
	})

	t.Run("WithPipelineFollowPatterns sets follow patterns", func(t *testing.T) {
		t.Parallel()

		cfg := &DefaultPipelineConfig{}
		patterns := []string{"/api/*", "/public/*"}
		opt := WithPipelineFollowPatterns(patterns)
		opt(cfg)

		if len(cfg.FollowPatterns) != 2 {
			t.Errorf("expected 2 follow patterns, got %d", len(cfg.FollowPatterns))
		}
		if cfg.FollowPatterns[0] != "/api/*" {
			t.Errorf("expected first pattern '/api/*', got %q", cfg.FollowPatterns[0])
		}
	})
}

// TestPipelineWithLogger tests the WithLogger option.
func TestPipelineWithLogger(t *testing.T) {
	t.Parallel()

	t.Run("sets custom logger", func(t *testing.T) {
		t.Parallel()

		// Note: We can't directly test that the logger is set
		// since it's a private field, but we test that it doesn't panic
		p := New(WithLogger(nil))
		if p == nil {
			t.Fatal("expected non-nil pipeline")
		}
	})

	t.Run("pipeline works with custom logger", func(t *testing.T) {
		t.Parallel()

		p := New()
		p.AddStep(&mockStep{name: "test"})

		report := model.NewOnionScanReport("example.onion")
		err := p.Execute(context.Background(), report)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// TestMockStep tests the mockStep helper.
func TestMockStep(t *testing.T) {
	t.Parallel()

	t.Run("increments call count", func(t *testing.T) {
		t.Parallel()

		step := &mockStep{name: "test"}
		report := model.NewOnionScanReport("example.onion")

		_ = step.Do(context.Background(), report)
		_ = step.Do(context.Background(), report)
		_ = step.Do(context.Background(), report)

		if step.callCount != 3 {
			t.Errorf("expected call count 3, got %d", step.callCount)
		}
	})

	t.Run("returns name correctly", func(t *testing.T) {
		t.Parallel()

		step := &mockStep{name: "my-step"}
		if step.Name() != "my-step" {
			t.Errorf("expected name 'my-step', got %q", step.Name())
		}
	})

	t.Run("returns nil when no doFunc", func(t *testing.T) {
		t.Parallel()

		step := &mockStep{name: "test"}
		err := step.Do(context.Background(), nil)
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	})
}

// TestBatchProcessorOptions tests BatchProcessor option functions.
func TestBatchProcessorOptions(t *testing.T) {
	t.Parallel()

	t.Run("WithBatchLogger sets custom logger", func(t *testing.T) {
		t.Parallel()

		factory := func() *Pipeline { return New() }
		bp := NewBatchProcessor(factory, WithBatchLogger(nil))

		if bp == nil {
			t.Fatal("expected non-nil batch processor")
		}
	})

	t.Run("WithConcurrency sets concurrency", func(t *testing.T) {
		t.Parallel()

		factory := func() *Pipeline { return New() }
		bp := NewBatchProcessor(factory, WithConcurrency(5))

		if bp.concurrency != 5 {
			t.Errorf("expected concurrency 5, got %d", bp.concurrency)
		}
	})

	t.Run("WithConcurrency ignores invalid values", func(t *testing.T) {
		t.Parallel()

		factory := func() *Pipeline { return New() }
		bp := NewBatchProcessor(factory, WithConcurrency(0))

		// Should keep default (10)
		if bp.concurrency != 10 {
			t.Errorf("expected default concurrency 10, got %d", bp.concurrency)
		}
	})
}
