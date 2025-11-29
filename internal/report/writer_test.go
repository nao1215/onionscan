package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nao1215/onionscan/internal/model"
)

// createTestReport creates a report with sample data for testing.
func createTestReport() *model.OnionScanReport {
	report := model.NewOnionScanReport("testservice.onion")
	report.WebDetected = true
	report.SSHDetected = true

	// Add some findings
	report.AnonymityReport.AddEmailAddress("test@example.com")
	report.AnonymityReport.ApacheModStatusFound = true
	report.AnonymityReport.AddAnalyticsID(model.AnalyticsID{
		ID:   "G-12345678",
		Type: "ga4",
	})

	// Generate simple report
	report.SimpleReport = model.NewSimpleReport(report)

	return report
}

// TestSimpleWriter tests the human-readable report writer.
func TestSimpleWriter(t *testing.T) {
	t.Parallel()

	t.Run("writes report header", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewSimpleWriter(&buf)
		report := createTestReport()

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "ONIONSCAN REPORT") {
			t.Error("expected output to contain header")
		}
		if !strings.Contains(output, "testservice.onion") {
			t.Error("expected output to contain hidden service address")
		}
	})

	t.Run("writes severity summary", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewSimpleWriter(&buf)
		report := createTestReport()

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "SEVERITY SUMMARY") {
			t.Error("expected output to contain severity summary")
		}
		if !strings.Contains(output, "HIGH:") {
			t.Error("expected output to contain HIGH count")
		}
	})

	t.Run("writes detected services", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewSimpleWriter(&buf)
		report := createTestReport()

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "HTTP (80)") {
			t.Error("expected output to contain HTTP service")
		}
		if !strings.Contains(output, "SSH (22)") {
			t.Error("expected output to contain SSH service")
		}
	})

	t.Run("writes findings", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewSimpleWriter(&buf)
		report := createTestReport()

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "Apache mod_status Exposed") {
			t.Error("expected output to contain Apache mod_status finding")
		}
		if !strings.Contains(output, "test@example.com") {
			t.Error("expected output to contain email address")
		}
	})

	t.Run("verbose mode includes descriptions", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewSimpleWriter(&buf, WithVerbose(true))
		report := createTestReport()

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "Description:") {
			t.Error("expected verbose output to contain descriptions")
		}
	})

	t.Run("handles timed out report", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewSimpleWriter(&buf)
		report := createTestReport()
		report.TimedOut = true
		report.SimpleReport = model.NewSimpleReport(report)

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "TIMED OUT") {
			t.Error("expected output to indicate timeout")
		}
	})
}

// TestJSONWriter tests the JSON report writer.
func TestJSONWriter(t *testing.T) {
	t.Parallel()

	t.Run("outputs valid JSON", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewJSONWriter(&buf)
		report := createTestReport()

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify it's valid JSON
		var parsed model.OnionScanReport
		if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}

		if parsed.HiddenService != "testservice.onion" {
			t.Errorf("expected hidden service %q, got %q",
				"testservice.onion", parsed.HiddenService)
		}
	})

	t.Run("compact output by default", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewJSONWriter(&buf)
		report := createTestReport()

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		// Compact JSON should be on fewer lines
		lines := strings.Split(strings.TrimSpace(output), "\n")
		if len(lines) > 1 {
			t.Errorf("expected compact output (1 line), got %d lines", len(lines))
		}
	})

	t.Run("pretty print with indent", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewJSONWriter(&buf, WithPrettyPrint())
		report := createTestReport()

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		// Pretty printed JSON should have multiple lines
		lines := strings.Split(strings.TrimSpace(output), "\n")
		if len(lines) < 5 {
			t.Errorf("expected multi-line output, got %d lines", len(lines))
		}
	})

	t.Run("WriteSimple outputs simple report", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewJSONWriter(&buf)
		simple := &model.SimpleReport{
			HiddenService: "test.onion",
			DateScanned:   time.Now(),
			CriticalCount: 1,
		}

		_, err := w.WriteSimple(simple)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var parsed model.SimpleReport
		if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}

		if parsed.CriticalCount != 1 {
			t.Errorf("expected critical count 1, got %d", parsed.CriticalCount)
		}
	})
}

// TestFullJSONWriter tests the full JSON writer with metadata.
func TestFullJSONWriter(t *testing.T) {
	t.Parallel()

	t.Run("includes version in output", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewFullJSONWriter(&buf, "2.0.0", WithPrettyPrint())
		report := createTestReport()

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var parsed JSONReport
		if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}

		if parsed.Version != "2.0.0" {
			t.Errorf("expected version %q, got %q", "2.0.0", parsed.Version)
		}
	})
}

// TestMultiWriter tests writing to multiple outputs.
func TestMultiWriter(t *testing.T) {
	t.Parallel()

	t.Run("writes to all writers", func(t *testing.T) {
		t.Parallel()

		var buf1, buf2 bytes.Buffer
		w1 := NewSimpleWriter(&buf1)
		w2 := NewJSONWriter(&buf2)

		multi := NewMultiWriter(w1, w2)
		report := createTestReport()

		_, err := multi.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Check both buffers have content
		if buf1.Len() == 0 {
			t.Error("expected buf1 to have content")
		}
		if buf2.Len() == 0 {
			t.Error("expected buf2 to have content")
		}

		// Verify formats are different
		if strings.Contains(buf1.String(), "{") {
			t.Error("expected buf1 (simple) to not be JSON")
		}
		if !strings.Contains(buf2.String(), "{") {
			t.Error("expected buf2 (JSON) to contain JSON")
		}
	})
}

// TestSimpleWriterSeverityIndicators tests severity indicators for all levels.
func TestSimpleWriterSeverityIndicators(t *testing.T) {
	t.Parallel()

	t.Run("shows all severity levels", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewSimpleWriter(&buf, WithShowEmpty(true))
		report := model.NewOnionScanReport("test.onion")
		report.SimpleReport = model.NewSimpleReport(report)

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		// With showEmpty, all severity levels should be shown
		if !strings.Contains(output, "[!!!]") {
			t.Error("expected critical indicator [!!!]")
		}
		if !strings.Contains(output, "[!!]") {
			t.Error("expected high indicator [!!]")
		}
		if !strings.Contains(output, "[!]") {
			t.Error("expected medium indicator [!]")
		}
		if !strings.Contains(output, "[-]") {
			t.Error("expected low indicator [-]")
		}
		if !strings.Contains(output, "[i]") {
			t.Error("expected info indicator [i]")
		}
	})
}

// TestSimpleWriterWithError tests report with error status.
func TestSimpleWriterWithError(t *testing.T) {
	t.Parallel()

	t.Run("shows error in status", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewSimpleWriter(&buf)
		report := model.NewOnionScanReport("error.onion")
		report.SimpleReport = model.NewSimpleReport(report)
		report.SimpleReport.Error = "connection timeout"

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "ERROR") {
			t.Error("expected ERROR in status")
		}
		if !strings.Contains(output, "connection timeout") {
			t.Error("expected error message in output")
		}
	})
}

// TestSimpleWriterWriteSimple tests WriteSimple method directly.
func TestSimpleWriterWriteSimple(t *testing.T) {
	t.Parallel()

	t.Run("writes simple report directly", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewSimpleWriter(&buf)

		simple := &model.SimpleReport{
			HiddenService: "direct.onion",
			DateScanned:   time.Now(),
			CriticalCount: 2,
			HighCount:     3,
			MediumCount:   5,
			LowCount:      10,
			InfoCount:     15,
		}

		_, err := w.WriteSimple(simple)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "direct.onion") {
			t.Error("expected hidden service in output")
		}
		if !strings.Contains(output, "CRITICAL: 2") {
			t.Error("expected critical count in output")
		}
		// TotalFindings() counts actual findings in the slice, not the sum of counts
		if !strings.Contains(output, "TOTAL:") {
			t.Error("expected total count in output")
		}
	})
}

// TestSimpleWriterNoServices tests report with no services detected.
func TestSimpleWriterNoServices(t *testing.T) {
	t.Parallel()

	t.Run("shows no services with showEmpty", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewSimpleWriter(&buf, WithShowEmpty(true))
		report := model.NewOnionScanReport("noservice.onion")
		report.SimpleReport = model.NewSimpleReport(report)

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "No services detected") {
			t.Error("expected 'No services detected' message")
		}
	})

	t.Run("hides services section without showEmpty", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewSimpleWriter(&buf)
		report := model.NewOnionScanReport("noservice.onion")
		report.SimpleReport = model.NewSimpleReport(report)

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		// Without showEmpty, should not contain "No services detected"
		if strings.Contains(output, "No services detected") {
			t.Error("should not show 'No services detected' without showEmpty")
		}
	})
}

// TestSimpleWriterWithFindingDetails tests findings with location and value.
func TestSimpleWriterWithFindingDetails(t *testing.T) {
	t.Parallel()

	t.Run("shows finding value and location", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewSimpleWriter(&buf, WithVerbose(true))
		report := model.NewOnionScanReport("details.onion")
		report.AnonymityReport.AddBitcoinAddress(model.CryptoAddress{
			Address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
			Type:    "legacy",
		})
		report.SimpleReport = model.NewSimpleReport(report)

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "Value:") {
			t.Error("expected Value: in output")
		}
	})
}

// TestWriteNilSimpleReport tests handling of nil SimpleReport.
func TestWriteNilSimpleReport(t *testing.T) {
	t.Parallel()

	t.Run("generates report when SimpleReport is nil", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewSimpleWriter(&buf)
		report := model.NewOnionScanReport("generate.onion")
		// Intentionally leave SimpleReport as nil
		report.SimpleReport = nil

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "generate.onion") {
			t.Error("expected hidden service in output")
		}
	})
}

// TestWithIndent tests the WithIndent JSON option.
func TestWithIndent(t *testing.T) {
	t.Parallel()

	t.Run("uses custom prefix and indent", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewJSONWriter(&buf, WithIndent(">>", "\t"))
		report := createTestReport()

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		// Should have multiple lines with custom formatting
		lines := strings.Split(strings.TrimSpace(output), "\n")
		if len(lines) < 5 {
			t.Errorf("expected multi-line output, got %d lines", len(lines))
		}
		// Check that prefix is used
		if !strings.Contains(output, ">>") {
			t.Error("expected custom prefix '>>' in output")
		}
		// Check that tab indent is used
		if !strings.Contains(output, "\t") {
			t.Error("expected tab indentation in output")
		}
	})

	t.Run("uses empty prefix with space indent", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewJSONWriter(&buf, WithIndent("", "    "))
		simple := &model.SimpleReport{
			HiddenService: "indent.onion",
			DateScanned:   time.Now(),
		}

		_, err := w.WriteSimple(simple)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		// Should have 4-space indentation
		if !strings.Contains(output, "    ") {
			t.Error("expected 4-space indentation in output")
		}
	})
}

// TestMultiWriterWriteSimple tests MultiWriter.WriteSimple method.
func TestMultiWriterWriteSimple(t *testing.T) {
	t.Parallel()

	t.Run("writes simple report to all writers", func(t *testing.T) {
		t.Parallel()

		var buf1, buf2 bytes.Buffer
		w1 := NewSimpleWriter(&buf1)
		w2 := NewJSONWriter(&buf2)

		multi := NewMultiWriter(w1, w2)
		simple := &model.SimpleReport{
			HiddenService: "multi.onion",
			DateScanned:   time.Now(),
			CriticalCount: 3,
			HighCount:     2,
		}

		n, err := multi.WriteSimple(simple)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n == 0 {
			t.Error("expected non-zero bytes written")
		}

		// Check both buffers have content
		if buf1.Len() == 0 {
			t.Error("expected buf1 to have content")
		}
		if buf2.Len() == 0 {
			t.Error("expected buf2 to have content")
		}

		// Verify content
		if !strings.Contains(buf1.String(), "multi.onion") {
			t.Error("expected hidden service in simple output")
		}
		if !strings.Contains(buf2.String(), "multi.onion") {
			t.Error("expected hidden service in JSON output")
		}
	})

	t.Run("handles empty writers list", func(t *testing.T) {
		t.Parallel()

		multi := NewMultiWriter()
		simple := &model.SimpleReport{
			HiddenService: "empty.onion",
		}

		n, err := multi.WriteSimple(simple)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != 0 {
			t.Errorf("expected 0 bytes written for empty writers, got %d", n)
		}
	})
}

// TestMarkdownWriter tests the Markdown report writer.
func TestMarkdownWriter(t *testing.T) {
	t.Parallel()

	t.Run("writes report header", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewMarkdownWriter(&buf)
		report := createTestReport()

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "# OnionScan Report") {
			t.Error("expected output to contain H1 header")
		}
		if !strings.Contains(output, "testservice.onion") {
			t.Error("expected output to contain hidden service address")
		}
	})

	t.Run("writes severity summary", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewMarkdownWriter(&buf)
		report := createTestReport()

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "## Severity Summary") {
			t.Error("expected output to contain severity summary header")
		}
		if !strings.Contains(output, "🔴 Critical") {
			t.Error("expected output to contain critical severity indicator")
		}
	})

	t.Run("writes detected services", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewMarkdownWriter(&buf)
		report := createTestReport()

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "## Detected Services") {
			t.Error("expected output to contain detected services header")
		}
		if !strings.Contains(output, "HTTP (80)") {
			t.Error("expected output to contain HTTP service")
		}
	})

	t.Run("writes findings table", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewMarkdownWriter(&buf)
		report := createTestReport()

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "## Findings") {
			t.Error("expected output to contain findings header")
		}
		if !strings.Contains(output, "Apache mod_status Exposed") {
			t.Error("expected output to contain mod_status finding")
		}
	})

	t.Run("handles timed out report", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewMarkdownWriter(&buf)
		report := createTestReport()
		report.TimedOut = true
		report.SimpleReport = model.NewSimpleReport(report)

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "Timed Out") {
			t.Error("expected output to indicate timeout")
		}
	})

	t.Run("includes GitHub alert for critical findings", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewMarkdownWriter(&buf)
		report := model.NewOnionScanReport("critical.onion")
		report.AnonymityReport.PrivateKeyExposed = true
		report.AnonymityReport.PrivateKeyType = "v3" // Use "v3" to match "private_key_v3" in severity map
		report.SimpleReport = model.NewSimpleReport(report)

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "[!CAUTION]") {
			t.Error("expected output to contain CAUTION alert for critical findings")
		}
	})

	t.Run("includes pie chart", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewMarkdownWriter(&buf)
		report := createTestReport()

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "pie") {
			t.Error("expected output to contain mermaid pie chart")
		}
	})

	t.Run("includes recommendations", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewMarkdownWriter(&buf)
		report := createTestReport()

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		// The table should have Recommendation column
		if !strings.Contains(output, "Recommendation") {
			t.Error("expected Recommendation column in output")
		}
	})

	t.Run("includes details", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewMarkdownWriter(&buf)
		report := createTestReport()

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		// Should include <details> tags
		if !strings.Contains(output, "<details>") {
			t.Error("expected output to contain details tags")
		}
	})

	t.Run("WriteSimple outputs simple report", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewMarkdownWriter(&buf)
		simple := &model.SimpleReport{
			HiddenService: "simple.onion",
			DateScanned:   time.Now(),
			CriticalCount: 0,
			HighCount:     1,
		}

		_, err := w.WriteSimple(simple)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "simple.onion") {
			t.Error("expected hidden service in output")
		}
	})

	t.Run("handles report with no findings", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewMarkdownWriter(&buf)
		report := model.NewOnionScanReport("empty.onion")
		report.SimpleReport = model.NewSimpleReport(report)

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "No security findings detected") {
			t.Error("expected message about no findings")
		}
		if !strings.Contains(output, "[!TIP]") {
			t.Error("expected TIP alert for no findings")
		}
	})

	t.Run("handles report with no services", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewMarkdownWriter(&buf)
		report := model.NewOnionScanReport("noservice.onion")
		report.SimpleReport = model.NewSimpleReport(report)

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "No network services detected") {
			t.Error("expected message about no services")
		}
	})

	t.Run("writes footer with link", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewMarkdownWriter(&buf)
		report := createTestReport()

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "OnionScan 2025") {
			t.Error("expected footer with version")
		}
		if !strings.Contains(output, "https://github.com/nao1215/onionscan") {
			t.Error("expected footer with repository link")
		}
	})
}

// TestMarkdownWriterWithError tests report with error status.
func TestMarkdownWriterWithError(t *testing.T) {
	t.Parallel()

	t.Run("shows error in status", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := NewMarkdownWriter(&buf)
		report := model.NewOnionScanReport("error.onion")
		report.SimpleReport = model.NewSimpleReport(report)
		report.SimpleReport.Error = "connection failed"

		_, err := w.Write(report)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "Error") {
			t.Error("expected Error in status")
		}
		if !strings.Contains(output, "connection failed") {
			t.Error("expected error message in output")
		}
	})
}

// TestTruncateString tests the string truncation helper.
func TestTruncateString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is a longer string", 10, "this is..."},
		{"abc", 3, "abc"},
		{"abcd", 3, "abc"},
		{"ab", 5, "ab"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			result := truncateString(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("truncateString(%q, %d) = %q, want %q",
					tt.input, tt.maxLen, result, tt.expected)
			}
		})
	}
}
