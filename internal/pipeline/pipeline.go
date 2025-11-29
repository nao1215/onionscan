package pipeline

import (
	"context"
	"log/slog"

	"github.com/nao1215/onionscan/internal/model"
)

// Step defines the interface that all pipeline steps must implement.
// Steps are executed in sequence, with each step receiving the accumulated
// report from previous steps.
//
// Design decision: We use an interface rather than function types because:
// 1. It allows steps to carry configuration state
// 2. It provides a Name() method for logging and debugging
// 3. It's more extensible for future features (e.g., priority, dependencies)
type Step interface {
	// Do executes the pipeline step.
	// It receives the context for cancellation, and the report to modify.
	// Returns an error if the step fails critically; non-critical errors
	// should be recorded in the report and return nil.
	Do(ctx context.Context, report *model.OnionScanReport) error

	// Name returns the step's name for logging purposes.
	Name() string
}

// Pipeline orchestrates the execution of multiple steps.
// It maintains a list of steps and executes them in order.
type Pipeline struct {
	// steps contains the ordered list of steps to execute.
	steps []Step

	// logger is used for structured logging during execution.
	logger *slog.Logger

	// continueOnError determines whether to continue executing steps
	// after one fails. If false, the pipeline stops on first error.
	continueOnError bool
}

// Option is a function that configures a Pipeline.
// This follows the functional options pattern for clean API design.
type Option func(*Pipeline)

// WithLogger sets a custom logger for the pipeline.
// If not set, a default logger is created.
func WithLogger(logger *slog.Logger) Option {
	return func(p *Pipeline) {
		p.logger = logger
	}
}

// WithContinueOnError configures the pipeline to continue execution
// even when a step fails. Failed steps are logged and their errors
// are recorded in the report, but subsequent steps still execute.
//
// Design decision: This option exists because some failures (e.g., timeout
// on one protocol) shouldn't prevent checking other protocols. However,
// the default is to stop on error because early failures often indicate
// fundamental problems (e.g., Tor not running).
func WithContinueOnError(continueOnError bool) Option {
	return func(p *Pipeline) {
		p.continueOnError = continueOnError
	}
}

// New creates a new Pipeline with the given options.
// Steps should be added using AddStep after creation.
func New(opts ...Option) *Pipeline {
	p := &Pipeline{
		steps:           make([]Step, 0),
		continueOnError: false,
	}

	// Apply options
	for _, opt := range opts {
		opt(p)
	}

	// Set default logger if not provided
	if p.logger == nil {
		p.logger = slog.Default()
	}

	return p
}

// AddStep appends a step to the pipeline.
// Steps are executed in the order they are added.
func (p *Pipeline) AddStep(step Step) {
	p.steps = append(p.steps, step)
}

// AddSteps appends multiple steps to the pipeline.
func (p *Pipeline) AddSteps(steps ...Step) {
	p.steps = append(p.steps, steps...)
}

// Execute runs all pipeline steps in sequence.
// It respects context cancellation and logs each step's execution.
//
// Design decision: We check context.Done() before each step rather than
// during, because steps should handle their own timeouts. This allows
// graceful cleanup between steps while still respecting cancellation.
//
// Returns the first error encountered if continueOnError is false,
// or nil if all steps complete (errors are recorded in report).
func (p *Pipeline) Execute(ctx context.Context, report *model.OnionScanReport) error {
	for _, step := range p.steps {
		// Check for cancellation before starting each step
		select {
		case <-ctx.Done():
			p.logger.Warn("pipeline cancelled",
				"step", step.Name(),
				"reason", ctx.Err(),
			)
			report.TimedOut = true
			return ctx.Err()
		default:
			// Continue with execution
		}

		p.logger.Info("executing step",
			"step", step.Name(),
			"service", report.HiddenService,
		)

		// Execute the step
		if err := step.Do(ctx, report); err != nil {
			p.logger.Error("step failed",
				"step", step.Name(),
				"service", report.HiddenService,
				"error", err,
			)

			// Record the error in the report
			report.Error = err
			report.ErrorMessage = err.Error()

			// Stop or continue based on configuration
			if !p.continueOnError {
				return err
			}
		} else {
			p.logger.Debug("step completed",
				"step", step.Name(),
				"service", report.HiddenService,
			)
		}

		// Track which steps were performed
		report.PerformedScans = append(report.PerformedScans, step.Name())
	}

	return nil
}

// StepCount returns the number of steps in the pipeline.
func (p *Pipeline) StepCount() int {
	return len(p.steps)
}

// StepNames returns the names of all steps in execution order.
func (p *Pipeline) StepNames() []string {
	names := make([]string, len(p.steps))
	for i, step := range p.steps {
		names[i] = step.Name()
	}
	return names
}
