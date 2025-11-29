package report

import (
	"encoding/json"
	"io"

	"github.com/nao1215/onionscan/internal/model"
)

// JSONWriter outputs reports in JSON format.
// This format is designed for tool integration and programmatic processing.
//
// Design decision: We use standard encoding/json rather than a third-party
// JSON library because:
// 1. It's part of the standard library (no extra dependencies)
// 2. It's sufficient for our needs
// 3. It provides consistent behavior across Go versions
type JSONWriter struct {
	baseWriter

	// indent enables pretty-printed JSON output.
	// When false, output is compact (no extra whitespace).
	indent bool

	// indentPrefix is the prefix for each line in indented output.
	indentPrefix string

	// indentString is the indentation string (typically "  " or "\t").
	indentString string
}

// JSONWriterOption configures a JSONWriter.
type JSONWriterOption func(*JSONWriter)

// WithIndent enables pretty-printed JSON output.
// The prefix is prepended to each line, and indent is used for each level.
func WithIndent(prefix, indent string) JSONWriterOption {
	return func(w *JSONWriter) {
		w.indent = true
		w.indentPrefix = prefix
		w.indentString = indent
	}
}

// WithPrettyPrint enables pretty-printed JSON with default indentation.
// This is a convenience wrapper for WithIndent("", "  ").
func WithPrettyPrint() JSONWriterOption {
	return func(w *JSONWriter) {
		w.indent = true
		w.indentPrefix = ""
		w.indentString = "  "
	}
}

// NewJSONWriter creates a JSONWriter that outputs to the given writer.
func NewJSONWriter(output io.Writer, opts ...JSONWriterOption) *JSONWriter {
	w := &JSONWriter{
		baseWriter:   newBaseWriter(output),
		indent:       false,
		indentPrefix: "",
		indentString: "",
	}

	for _, opt := range opts {
		opt(w)
	}

	return w
}

// Write outputs the full report in JSON format.
func (w *JSONWriter) Write(report *model.OnionScanReport) (int, error) {
	// Ensure SimpleReport is generated
	if report.SimpleReport == nil {
		report.SimpleReport = model.NewSimpleReport(report)
	}

	return w.writeJSON(report)
}

// WriteSimple outputs only the simple report in JSON format.
func (w *JSONWriter) WriteSimple(report *model.SimpleReport) (int, error) {
	return w.writeJSON(report)
}

// writeJSON marshals the given value to JSON and writes it to the output.
func (w *JSONWriter) writeJSON(v interface{}) (int, error) {
	var data []byte
	var err error

	if w.indent {
		data, err = json.MarshalIndent(v, w.indentPrefix, w.indentString)
	} else {
		data, err = json.Marshal(v)
	}

	if err != nil {
		return 0, err
	}

	// Add trailing newline for better terminal output
	data = append(data, '\n')

	return w.output.Write(data)
}

// JSONReport is a wrapper for the full report with additional metadata.
// This is used when writing the complete report with contextual information.
//
// Design decision: We wrap the report rather than modifying OnionScanReport
// because this allows us to add output-specific fields without polluting
// the core data structure.
type JSONReport struct {
	// Version is the OnionScan version that generated this report.
	Version string `json:"version"`

	// Report is the full scan report.
	Report *model.OnionScanReport `json:"report"`

	// Summary is the simple report for quick access.
	Summary *model.SimpleReport `json:"summary,omitempty"`
}

// NewJSONReport creates a JSONReport wrapper with version information.
func NewJSONReport(report *model.OnionScanReport, version string) *JSONReport {
	return &JSONReport{
		Version: version,
		Report:  report,
		Summary: report.SimpleReport,
	}
}

// FullJSONWriter outputs complete reports with metadata wrapper.
type FullJSONWriter struct {
	*JSONWriter

	// version is the OnionScan version string.
	version string
}

// NewFullJSONWriter creates a writer for complete reports with metadata.
func NewFullJSONWriter(output io.Writer, version string, opts ...JSONWriterOption) *FullJSONWriter {
	return &FullJSONWriter{
		JSONWriter: NewJSONWriter(output, opts...),
		version:    version,
	}
}

// Write outputs the full report wrapped with metadata.
func (w *FullJSONWriter) Write(report *model.OnionScanReport) (int, error) {
	// Ensure SimpleReport is generated
	if report.SimpleReport == nil {
		report.SimpleReport = model.NewSimpleReport(report)
	}

	wrapped := NewJSONReport(report, w.version)
	return w.writeJSON(wrapped)
}
