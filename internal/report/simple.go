package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/nao1215/onionscan/internal/model"
)

// SimpleWriter outputs human-readable text reports.
// This format is designed for terminal display with color-coded severity
// levels and clear section formatting.
//
// Design decision: We use plain text with ASCII formatting rather than
// ANSI colors by default because:
// 1. It works in all terminals without compatibility issues
// 2. It's easier to pipe to files or other tools
// 3. Color can be added as an option later if needed
type SimpleWriter struct {
	baseWriter

	// showEmpty controls whether sections with no findings are shown.
	showEmpty bool

	// verbose enables additional detail in the output.
	verbose bool
}

// SimpleWriterOption configures a SimpleWriter.
type SimpleWriterOption func(*SimpleWriter)

// WithShowEmpty configures the writer to show empty sections.
func WithShowEmpty(show bool) SimpleWriterOption {
	return func(w *SimpleWriter) {
		w.showEmpty = show
	}
}

// WithVerbose enables verbose output with additional details.
func WithVerbose(verbose bool) SimpleWriterOption {
	return func(w *SimpleWriter) {
		w.verbose = verbose
	}
}

// NewSimpleWriter creates a SimpleWriter that outputs to the given writer.
func NewSimpleWriter(output io.Writer, opts ...SimpleWriterOption) *SimpleWriter {
	w := &SimpleWriter{
		baseWriter: newBaseWriter(output),
		showEmpty:  false,
		verbose:    false,
	}

	for _, opt := range opts {
		opt(w)
	}

	return w
}

// Write outputs the full report in human-readable format.
// It generates a SimpleReport from the OnionScanReport if not already present.
func (w *SimpleWriter) Write(report *model.OnionScanReport) (int, error) {
	// Generate simple report if not already done
	simple := report.SimpleReport
	if simple == nil {
		simple = model.NewSimpleReport(report)
	}

	return w.WriteSimple(simple)
}

// WriteSimple outputs the simple report in human-readable format.
func (w *SimpleWriter) WriteSimple(report *model.SimpleReport) (int, error) {
	var sb strings.Builder

	// Header
	w.writeHeader(&sb, report)

	// Summary
	w.writeSummary(&sb, report)

	// Detected Services
	w.writeServices(&sb, report)

	// Findings by severity
	w.writeFindings(&sb, report)

	// Footer
	w.writeFooter(&sb, report)

	// Write to output
	return w.output.Write([]byte(sb.String()))
}

// writeHeader writes the report header with scan information.
func (w *SimpleWriter) writeHeader(sb *strings.Builder, report *model.SimpleReport) {
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("=", 70))
	sb.WriteString("\n")
	sb.WriteString("                         ONIONSCAN REPORT\n")
	sb.WriteString(strings.Repeat("=", 70))
	sb.WriteString("\n\n")

	sb.WriteString(fmt.Sprintf("Hidden Service: %s\n", report.HiddenService))
	sb.WriteString(fmt.Sprintf("Scan Date:      %s\n", report.DateScanned.Format("2006-01-02 15:04:05 MST")))
	sb.WriteString(fmt.Sprintf("Pages Crawled:  %d\n", report.PagesCrawled))

	if report.TimedOut {
		sb.WriteString("Status:         TIMED OUT (partial results)\n")
	} else if report.Error != "" {
		sb.WriteString(fmt.Sprintf("Status:         ERROR - %s\n", report.Error))
	} else {
		sb.WriteString("Status:         Complete\n")
	}

	sb.WriteString("\n")
}

// writeSummary writes the severity summary section.
func (w *SimpleWriter) writeSummary(sb *strings.Builder, report *model.SimpleReport) {
	sb.WriteString(strings.Repeat("-", 70))
	sb.WriteString("\n")
	sb.WriteString("SEVERITY SUMMARY\n")
	sb.WriteString(strings.Repeat("-", 70))
	sb.WriteString("\n\n")

	// Create a visual summary
	sb.WriteString(fmt.Sprintf("  CRITICAL: %d\n", report.CriticalCount))
	sb.WriteString(fmt.Sprintf("  HIGH:     %d\n", report.HighCount))
	sb.WriteString(fmt.Sprintf("  MEDIUM:   %d\n", report.MediumCount))
	sb.WriteString(fmt.Sprintf("  LOW:      %d\n", report.LowCount))
	sb.WriteString(fmt.Sprintf("  INFO:     %d\n", report.InfoCount))
	sb.WriteString("\n")

	total := report.TotalFindings()
	sb.WriteString(fmt.Sprintf("  TOTAL:    %d findings\n", total))
	sb.WriteString("\n")
}

// writeServices writes the detected services section.
func (w *SimpleWriter) writeServices(sb *strings.Builder, report *model.SimpleReport) {
	if len(report.DetectedServices) == 0 && !w.showEmpty {
		return
	}

	sb.WriteString(strings.Repeat("-", 70))
	sb.WriteString("\n")
	sb.WriteString("DETECTED SERVICES\n")
	sb.WriteString(strings.Repeat("-", 70))
	sb.WriteString("\n\n")

	if len(report.DetectedServices) == 0 {
		sb.WriteString("  No services detected\n")
	} else {
		for _, service := range report.DetectedServices {
			sb.WriteString(fmt.Sprintf("  [+] %s\n", service))
		}
	}
	sb.WriteString("\n")
}

// writeFindings writes all findings grouped by severity.
func (w *SimpleWriter) writeFindings(sb *strings.Builder, report *model.SimpleReport) {
	if !report.HasFindings() && !w.showEmpty {
		return
	}

	sb.WriteString(strings.Repeat("-", 70))
	sb.WriteString("\n")
	sb.WriteString("FINDINGS\n")
	sb.WriteString(strings.Repeat("-", 70))
	sb.WriteString("\n\n")

	// Write findings in order of severity (critical first)
	severities := []model.Severity{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
		model.SeverityInfo,
	}

	for _, severity := range severities {
		findings := report.GetFindingsBySeverity(severity)
		if len(findings) == 0 && !w.showEmpty {
			continue
		}

		w.writeFindingsForSeverity(sb, severity, findings)
	}
}

// writeFindingsForSeverity writes findings of a specific severity level.
func (w *SimpleWriter) writeFindingsForSeverity(sb *strings.Builder, severity model.Severity, findings []model.Finding) {
	// Severity header with visual indicator
	indicator := w.getSeverityIndicator(severity)
	sb.WriteString(fmt.Sprintf("[%s] %s\n", indicator, severity.String()))

	if len(findings) == 0 {
		sb.WriteString("  No findings\n\n")
		return
	}

	for _, finding := range findings {
		sb.WriteString(fmt.Sprintf("  * %s\n", finding.Title))
		if finding.Value != "" {
			sb.WriteString(fmt.Sprintf("    Value: %s\n", finding.Value))
		}
		if finding.Location != "" {
			sb.WriteString(fmt.Sprintf("    Location: %s\n", finding.Location))
		}
		if w.verbose && finding.Description != "" {
			sb.WriteString(fmt.Sprintf("    Description: %s\n", finding.Description))
		}
	}
	sb.WriteString("\n")
}

// getSeverityIndicator returns a visual indicator for the severity level.
func (w *SimpleWriter) getSeverityIndicator(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical:
		return "!!!"
	case model.SeverityHigh:
		return "!!"
	case model.SeverityMedium:
		return "!"
	case model.SeverityLow:
		return "-"
	case model.SeverityInfo:
		return "i"
	default:
		return "?"
	}
}

// writeFooter writes the report footer.
func (w *SimpleWriter) writeFooter(sb *strings.Builder, _ *model.SimpleReport) {
	sb.WriteString(strings.Repeat("=", 70))
	sb.WriteString("\n")
	sb.WriteString("Report generated by OnionScan 2025\n")
	sb.WriteString("https://github.com/nao1215/onionscan\n")
	sb.WriteString(strings.Repeat("=", 70))
	sb.WriteString("\n")
}
