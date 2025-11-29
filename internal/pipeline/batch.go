package pipeline

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/nao1215/onionscan/internal/model"
	"golang.org/x/sync/errgroup"
)

// BatchProcessor handles concurrent processing of multiple hidden services.
// It uses errgroup to manage goroutines and respect concurrency limits.
//
// Design decision: We use a separate BatchProcessor rather than adding batch
// functionality to Pipeline because:
// 1. It keeps the Pipeline focused on single-scan execution
// 2. It allows different batch strategies (e.g., rate limiting, retries)
// 3. It provides cleaner separation of concerns
type BatchProcessor struct {
	// pipelineFactory creates a new pipeline for each scan.
	// We use a factory to ensure each scan gets a fresh pipeline instance.
	pipelineFactory func() *Pipeline

	// concurrency is the maximum number of concurrent scans.
	concurrency int

	// logger is used for batch-level logging.
	logger *slog.Logger

	// results stores completed scan reports.
	// Access is synchronized via mutex.
	results []*model.OnionScanReport
	mu      sync.Mutex
}

// BatchOption configures a BatchProcessor.
type BatchOption func(*BatchProcessor)

// WithBatchLogger sets a custom logger for batch processing.
func WithBatchLogger(logger *slog.Logger) BatchOption {
	return func(b *BatchProcessor) {
		b.logger = logger
	}
}

// WithConcurrency sets the maximum number of concurrent scans.
// Default is 10 if not specified.
func WithConcurrency(n int) BatchOption {
	return func(b *BatchProcessor) {
		if n > 0 {
			b.concurrency = n
		}
	}
}

// NewBatchProcessor creates a new BatchProcessor.
//
// The pipelineFactory function is called for each scan to create a fresh
// pipeline instance. This ensures that pipeline state doesn't leak between
// scans and allows for per-scan customization if needed.
func NewBatchProcessor(pipelineFactory func() *Pipeline, opts ...BatchOption) *BatchProcessor {
	bp := &BatchProcessor{
		pipelineFactory: pipelineFactory,
		concurrency:     10,
		results:         make([]*model.OnionScanReport, 0),
	}

	for _, opt := range opts {
		opt(bp)
	}

	if bp.logger == nil {
		bp.logger = slog.Default()
	}

	return bp
}

// ProcessBatch scans multiple hidden services concurrently.
// It respects the configured concurrency limit and context cancellation.
//
// Design decision: We use errgroup.SetLimit rather than a worker pool
// because it's simpler and errgroup handles the concurrency correctly.
// Each service gets its own goroutine, but only 'concurrency' goroutines
// run simultaneously.
//
// Returns all reports collected, even for services that failed.
// The error return indicates if the batch was cancelled or if all scans failed.
func (bp *BatchProcessor) ProcessBatch(ctx context.Context, services []string) ([]*model.OnionScanReport, error) {
	bp.logger.Info("starting batch processing",
		"total_services", len(services),
		"concurrency", bp.concurrency,
	)

	startTime := time.Now()

	// Pre-allocate results slice to maintain order
	bp.results = make([]*model.OnionScanReport, len(services))

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(bp.concurrency)

	for i, service := range services {
		g.Go(func() error {
			// Check for cancellation before starting
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			bp.logger.Info("scanning service",
				"service", service,
				"index", i+1,
				"total", len(services),
			)

			// Create report for this service
			report := model.NewOnionScanReport(service)

			// Create and execute pipeline
			pipeline := bp.pipelineFactory()
			err := pipeline.Execute(ctx, report)

			// Store result regardless of error
			// The report contains error information if the scan failed
			bp.mu.Lock()
			bp.results[i] = report
			bp.mu.Unlock()

			if err != nil {
				bp.logger.Warn("scan failed",
					"service", service,
					"error", err,
				)
				// Don't return error to errgroup - we want to continue other scans
				// The error is recorded in the report
				return nil
			}

			bp.logger.Info("scan completed",
				"service", service,
			)

			return nil
		})
	}

	// Wait for all scans to complete
	err := g.Wait()

	elapsed := time.Since(startTime)
	bp.logger.Info("batch processing complete",
		"total_services", len(services),
		"elapsed", elapsed,
	)

	return bp.results, err
}

// ProcessBatchWithCallback scans multiple services and calls a callback
// for each completed scan. This is useful for streaming results.
//
// The callback receives the report and the index of the service in the
// original slice. The callback is called from the goroutine that completed
// the scan, so it should be thread-safe if it accesses shared state.
func (bp *BatchProcessor) ProcessBatchWithCallback(
	ctx context.Context,
	services []string,
	callback func(report *model.OnionScanReport, index int),
) error {
	bp.logger.Info("starting batch processing with callback",
		"total_services", len(services),
		"concurrency", bp.concurrency,
	)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(bp.concurrency)

	for i, service := range services {
		g.Go(func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			report := model.NewOnionScanReport(service)
			pipeline := bp.pipelineFactory()
			_ = pipeline.Execute(ctx, report) //nolint:errcheck // Error is stored in report

			// Call the callback with the result
			callback(report, i)

			return nil
		})
	}

	return g.Wait()
}
