package report

import (
	"io"

	"github.com/nao1215/onionscan/internal/model"
)

// Writer defines the interface for report output.
// Implementations write scan results in various formats.
//
// Design decision: We use an interface to allow different output formats
// and destinations. This enables writing to files, stdout, or network
// connections with the same API.
type Writer interface {
	// Write outputs the report to the configured destination.
	// Returns the number of bytes written and any error encountered.
	Write(report *model.OnionScanReport) (int, error)

	// WriteSimple outputs only the simple report portion.
	// This is useful for quick summaries without full details.
	WriteSimple(report *model.SimpleReport) (int, error)
}

// MultiWriter writes to multiple Writers simultaneously.
// This is useful for outputting to both terminal and file.
//
// Design decision: We implement this as a separate type rather than
// using io.MultiWriter because our Writer interface is different
// from io.Writer - we write reports, not raw bytes.
type MultiWriter struct {
	writers []Writer
}

// NewMultiWriter creates a Writer that writes to all provided Writers.
func NewMultiWriter(writers ...Writer) *MultiWriter {
	return &MultiWriter{writers: writers}
}

// Write outputs the report to all configured Writers.
// Returns the total bytes written across all writers.
// Stops on first error encountered.
func (m *MultiWriter) Write(report *model.OnionScanReport) (int, error) {
	var total int
	for _, w := range m.writers {
		n, err := w.Write(report)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// WriteSimple outputs the simple report to all configured Writers.
func (m *MultiWriter) WriteSimple(report *model.SimpleReport) (int, error) {
	var total int
	for _, w := range m.writers {
		n, err := w.WriteSimple(report)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// baseWriter provides common functionality for report writers.
type baseWriter struct {
	output io.Writer
}

// newBaseWriter creates a baseWriter with the given output destination.
func newBaseWriter(output io.Writer) baseWriter {
	return baseWriter{output: output}
}
