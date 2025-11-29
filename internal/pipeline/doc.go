// Package pipeline provides a framework for executing scan steps in sequence.
//
// The pipeline pattern is used to process hidden services through multiple
// stages: protocol scanning, web crawling, deanonymization checks, and report
// generation. Each stage is implemented as a PipelineStep that receives the
// current report and can modify it.
//
// Design decision: We use a pipeline pattern instead of direct function calls
// because:
// 1. It allows easy addition/removal of steps without modifying core logic
// 2. It provides consistent error handling and logging across steps
// 3. It supports cancellation via context for long-running scans
// 4. It enables potential parallelization of independent steps in the future
//
// The pipeline supports both individual scans and batch processing with
// concurrency control using errgroup.
package pipeline
