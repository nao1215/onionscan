package report

import (
	"io"
	"strconv"

	"github.com/nao1215/markdown"
	"github.com/nao1215/markdown/mermaid/piechart"
	"github.com/nao1215/onionscan/internal/model"
)

// MarkdownWriter outputs reports in Markdown format.
// This format is designed for documentation and sharing.
//
// Design decision: We use the nao1215/markdown library for fluent markdown
// generation which provides:
// 1. Type-safe markdown generation
// 2. Support for tables, lists, and code blocks
// 3. GitHub-flavored markdown alerts
type MarkdownWriter struct {
	baseWriter
}

// NewMarkdownWriter creates a MarkdownWriter that outputs to the given writer.
func NewMarkdownWriter(output io.Writer) *MarkdownWriter {
	return &MarkdownWriter{
		baseWriter: newBaseWriter(output),
	}
}

// Write outputs the full report in Markdown format.
func (w *MarkdownWriter) Write(report *model.OnionScanReport) (int, error) {
	simple := report.SimpleReport
	if simple == nil {
		simple = model.NewSimpleReport(report)
	}

	return w.WriteSimple(simple)
}

// WriteSimple outputs the simple report in Markdown format.
func (w *MarkdownWriter) WriteSimple(report *model.SimpleReport) (int, error) {
	md := markdown.NewMarkdown(w.output)

	// Header
	w.writeHeader(md, report)

	// Summary
	w.writeSummary(md, report)

	// Detected Services
	w.writeServices(md, report)

	// Findings by severity
	w.writeFindings(md, report)

	// Footer
	w.writeFooter(md)

	return len(md.String()), md.Build()
}

// writeHeader writes the report header with scan information.
func (w *MarkdownWriter) writeHeader(md *markdown.Markdown, report *model.SimpleReport) {
	md.H1("OnionScan Report")
	md.PlainText("")

	// Basic info table
	md.Table(markdown.TableSet{
		Header: []string{"Property", "Value"},
		Rows: [][]string{
			{"Hidden Service", "`" + report.HiddenService + "`"},
			{"Scan Date", report.DateScanned.Format("2006-01-02 15:04:05 MST")},
			{"Pages Crawled", strconv.Itoa(report.PagesCrawled)},
			{"Status", w.getStatusText(report)},
		},
	})
	md.PlainText("")
}

// getStatusText returns the status text based on report state.
func (w *MarkdownWriter) getStatusText(report *model.SimpleReport) string {
	if report.TimedOut {
		return "⚠️ Timed Out (partial results)"
	}
	if report.Error != "" {
		return "❌ Error - " + report.Error
	}
	return "✅ Complete"
}

// writeSummary writes the severity summary section.
func (w *MarkdownWriter) writeSummary(md *markdown.Markdown, report *model.SimpleReport) {
	md.H2("Severity Summary")
	md.PlainText("")

	// Summary table
	md.Table(markdown.TableSet{
		Header: []string{"Severity", "Count"},
		Rows: [][]string{
			{"🔴 Critical", strconv.Itoa(report.CriticalCount)},
			{"🟠 High", strconv.Itoa(report.HighCount)},
			{"🟡 Medium", strconv.Itoa(report.MediumCount)},
			{"🔵 Low", strconv.Itoa(report.LowCount)},
			{"⚪ Info", strconv.Itoa(report.InfoCount)},
			{"**Total**", "**" + strconv.Itoa(report.TotalFindings()) + "**"},
		},
	})
	md.PlainText("")

	// Add pie chart if there are findings
	if report.HasFindings() {
		w.writePieChart(md, report)
	}

	// Add alert based on severity
	w.writeAlert(md, report)
}

// writePieChart writes a mermaid pie chart for severity distribution.
func (w *MarkdownWriter) writePieChart(md *markdown.Markdown, report *model.SimpleReport) {
	chart := piechart.NewPieChart(
		io.Discard,
		piechart.WithTitle("Finding Severity Distribution"),
		piechart.WithShowData(true),
	)

	if report.CriticalCount > 0 {
		chart.LabelAndIntValue("Critical", uint64(report.CriticalCount))
	}
	if report.HighCount > 0 {
		chart.LabelAndIntValue("High", uint64(report.HighCount))
	}
	if report.MediumCount > 0 {
		chart.LabelAndIntValue("Medium", uint64(report.MediumCount))
	}
	if report.LowCount > 0 {
		chart.LabelAndIntValue("Low", uint64(report.LowCount))
	}
	if report.InfoCount > 0 {
		chart.LabelAndIntValue("Info", uint64(report.InfoCount))
	}

	md.PlainText("")
	md.CodeBlocks(markdown.SyntaxHighlightMermaid, chart.String())
	md.PlainText("")
}

// writeAlert writes an appropriate alert based on severity counts.
func (w *MarkdownWriter) writeAlert(md *markdown.Markdown, report *model.SimpleReport) {
	switch {
	case report.CriticalCount > 0:
		md.Cautionf(
			"Critical security issues detected! %d critical finding(s) require immediate attention.",
			report.CriticalCount,
		)
	case report.HighCount > 0:
		md.Warningf(
			"High severity issues detected. %d high severity finding(s) should be addressed.",
			report.HighCount,
		)
	case report.MediumCount > 0:
		md.Importantf(
			"Medium severity issues found. %d finding(s) may impact anonymity.",
			report.MediumCount,
		)
	case report.TotalFindings() > 0:
		md.Note("Only low severity and informational findings detected.")
	default:
		md.Tip("No significant security issues detected.")
	}
	md.PlainText("")
}

// writeServices writes the detected services section.
func (w *MarkdownWriter) writeServices(md *markdown.Markdown, report *model.SimpleReport) {
	md.H2("Detected Services")
	md.PlainText("")

	if len(report.DetectedServices) == 0 {
		md.PlainText("No network services detected.")
		md.PlainText("")
		return
	}

	md.BulletList(report.DetectedServices...)
	md.PlainText("")
}

// writeFindings writes all findings grouped by severity.
func (w *MarkdownWriter) writeFindings(md *markdown.Markdown, report *model.SimpleReport) {
	if !report.HasFindings() {
		md.H2("Findings")
		md.PlainText("")
		md.PlainText("No security findings detected.")
		md.PlainText("")
		return
	}

	md.H2("Findings")
	md.PlainText("")

	severities := []struct {
		level  model.Severity
		header string
	}{
		{model.SeverityCritical, "### 🔴 Critical"},
		{model.SeverityHigh, "### 🟠 High"},
		{model.SeverityMedium, "### 🟡 Medium"},
		{model.SeverityLow, "### 🔵 Low"},
		{model.SeverityInfo, "### ⚪ Info"},
	}

	for _, sev := range severities {
		findings := report.GetFindingsBySeverity(sev.level)
		if len(findings) == 0 {
			continue
		}

		md.PlainText(sev.header)
		md.PlainText("")
		w.writeFindingsTable(md, findings)
	}
}

// writeFindingsTable writes a table of findings with details.
func (w *MarkdownWriter) writeFindingsTable(md *markdown.Markdown, findings []model.Finding) {
	headers := []string{"Title", "Value", "Location", "Recommendation"}

	rows := make([][]string, len(findings))
	for i, f := range findings {
		value := f.Value
		if value == "" {
			value = "-"
		}
		location := f.Location
		if location == "" {
			location = "-"
		}
		rec := f.Recommendation
		if rec == "" {
			rec = "-"
		}

		rows[i] = []string{
			f.Title,
			truncateString(value, 50),
			truncateString(location, 40),
			truncateString(rec, 60),
		}
	}

	md.Table(markdown.TableSet{
		Header: headers,
		Rows:   rows,
	})
	md.PlainText("")

	// Add detailed descriptions for all findings
	for _, f := range findings {
		if f.Description != "" {
			md.Details(f.Title, f.Description)
		}
	}
	md.PlainText("")
}

// writeFooter writes the report footer.
func (w *MarkdownWriter) writeFooter(md *markdown.Markdown) {
	md.HorizontalRule()
	md.PlainText("")
	md.PlainTextf("*Report generated by [OnionScan 2025](https://github.com/nao1215/onionscan)*")
}

// truncateString truncates a string to maxLen characters with ellipsis.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
