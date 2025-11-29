package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nao1215/onionscan/internal/database"
	"github.com/nao1215/onionscan/internal/model"
)

func TestNewCompareCmd(t *testing.T) {
	t.Parallel()

	cmd := NewCompareCmd()

	if cmd.Use != "compare [onion-address]" {
		t.Errorf("unexpected Use: got %q", cmd.Use)
	}

	// Verify flags exist with their short options
	flagsWithShort := map[string]string{
		"list":          "l",
		"list-services": "L",
		"with-scan-id":  "i",
		"since":         "s",
		"json":          "j",
		"markdown":      "m",
	}
	for flag, shorthand := range flagsWithShort {
		f := cmd.Flags().Lookup(flag)
		if f == nil {
			t.Errorf("expected flag %q to exist", flag)
			continue
		}
		if f.Shorthand != shorthand {
			t.Errorf("flag %q: expected shorthand %q, got %q", flag, shorthand, f.Shorthand)
		}
	}

	// Verify db-dir flag does NOT exist (uses XDG directory)
	if cmd.Flags().Lookup("db-dir") != nil {
		t.Error("db-dir flag should not exist")
	}
}

func TestNewCompareCmdFlags(t *testing.T) {
	t.Parallel()

	cmd := NewCompareCmd()

	t.Run("has correct use", func(t *testing.T) {
		t.Parallel()
		if cmd.Use != "compare [onion-address]" {
			t.Errorf("unexpected Use: got %q", cmd.Use)
		}
	})

	t.Run("has short description", func(t *testing.T) {
		t.Parallel()
		if cmd.Short == "" {
			t.Error("expected non-empty Short description")
		}
	})

	t.Run("has long description", func(t *testing.T) {
		t.Parallel()
		if cmd.Long == "" {
			t.Error("expected non-empty Long description")
		}
	})

	t.Run("list flag has shorthand l", func(t *testing.T) {
		t.Parallel()
		flag := cmd.Flags().Lookup("list")
		if flag == nil {
			t.Fatal("expected list flag")
		}
		if flag.Shorthand != "l" {
			t.Errorf("expected shorthand 'l', got %q", flag.Shorthand)
		}
	})

	t.Run("list-services flag has shorthand L", func(t *testing.T) {
		t.Parallel()
		flag := cmd.Flags().Lookup("list-services")
		if flag == nil {
			t.Fatal("expected list-services flag")
		}
		if flag.Shorthand != "L" {
			t.Errorf("expected shorthand 'L', got %q", flag.Shorthand)
		}
	})

	t.Run("with-scan-id flag has shorthand i", func(t *testing.T) {
		t.Parallel()
		flag := cmd.Flags().Lookup("with-scan-id")
		if flag == nil {
			t.Fatal("expected with-scan-id flag")
		}
		if flag.Shorthand != "i" {
			t.Errorf("expected shorthand 'i', got %q", flag.Shorthand)
		}
	})

	t.Run("since flag has shorthand s", func(t *testing.T) {
		t.Parallel()
		flag := cmd.Flags().Lookup("since")
		if flag == nil {
			t.Fatal("expected since flag")
		}
		if flag.Shorthand != "s" {
			t.Errorf("expected shorthand 's', got %q", flag.Shorthand)
		}
	})

	t.Run("json flag has shorthand j", func(t *testing.T) {
		t.Parallel()
		flag := cmd.Flags().Lookup("json")
		if flag == nil {
			t.Fatal("expected json flag")
		}
		if flag.Shorthand != "j" {
			t.Errorf("expected shorthand 'j', got %q", flag.Shorthand)
		}
	})

	t.Run("markdown flag has shorthand m", func(t *testing.T) {
		t.Parallel()
		flag := cmd.Flags().Lookup("markdown")
		if flag == nil {
			t.Fatal("expected markdown flag")
		}
		if flag.Shorthand != "m" {
			t.Errorf("expected shorthand 'm', got %q", flag.Shorthand)
		}
	})

	t.Run("accepts maximum 1 argument", func(t *testing.T) {
		t.Parallel()
		// cobra.MaximumNArgs(1) is used
		if cmd.Args == nil {
			t.Error("expected Args to be set")
		}
	})
}

func TestCompareReports(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		previousFindings  []model.Finding
		currentFindings   []model.Finding
		wantNewCount      int
		wantResolvedCount int
		wantUnchanged     int
		wantDirection     string
	}{
		{
			name:              "no changes when findings are identical",
			previousFindings:  []model.Finding{{Type: "email_address", Value: "test@example.com", Severity: model.SeverityMedium, SeverityText: "Medium"}},
			currentFindings:   []model.Finding{{Type: "email_address", Value: "test@example.com", Severity: model.SeverityMedium, SeverityText: "Medium"}},
			wantNewCount:      0,
			wantResolvedCount: 0,
			wantUnchanged:     1,
			wantDirection:     "unchanged",
		},
		{
			name:              "detects new findings",
			previousFindings:  []model.Finding{},
			currentFindings:   []model.Finding{{Type: "email_address", Value: "new@example.com", Severity: model.SeverityMedium, SeverityText: "Medium"}},
			wantNewCount:      1,
			wantResolvedCount: 0,
			wantUnchanged:     0,
			wantDirection:     "worsened",
		},
		{
			name:              "detects resolved findings",
			previousFindings:  []model.Finding{{Type: "email_address", Value: "old@example.com", Severity: model.SeverityMedium, SeverityText: "Medium"}},
			currentFindings:   []model.Finding{},
			wantNewCount:      0,
			wantResolvedCount: 1,
			wantUnchanged:     0,
			wantDirection:     "improved",
		},
		{
			name: "handles mixed changes",
			previousFindings: []model.Finding{
				{Type: "email_address", Value: "unchanged@example.com", Severity: model.SeverityMedium, SeverityText: "Medium"},
				{Type: "email_address", Value: "resolved@example.com", Severity: model.SeverityMedium, SeverityText: "Medium"},
			},
			currentFindings: []model.Finding{
				{Type: "email_address", Value: "unchanged@example.com", Severity: model.SeverityMedium, SeverityText: "Medium"},
				{Type: "email_address", Value: "new@example.com", Severity: model.SeverityMedium, SeverityText: "Medium"},
			},
			wantNewCount:      1,
			wantResolvedCount: 1,
			wantUnchanged:     1,
			wantDirection:     "unchanged",
		},
		{
			name:              "critical finding causes worsened status",
			previousFindings:  []model.Finding{},
			currentFindings:   []model.Finding{{Type: "clearnet_ip", Value: "192.168.1.1", Severity: model.SeverityCritical, SeverityText: "Critical"}},
			wantNewCount:      1,
			wantResolvedCount: 0,
			wantUnchanged:     0,
			wantDirection:     "worsened",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			previous := &model.OnionScanReport{
				HiddenService: "test.onion",
				DateScanned:   time.Now().Add(-24 * time.Hour),
				SimpleReport: &model.SimpleReport{
					Findings: tt.previousFindings,
				},
			}
			// Count severities for previous
			for _, f := range tt.previousFindings {
				switch f.Severity {
				case model.SeverityCritical:
					previous.SimpleReport.CriticalCount++
				case model.SeverityHigh:
					previous.SimpleReport.HighCount++
				case model.SeverityMedium:
					previous.SimpleReport.MediumCount++
				case model.SeverityLow:
					previous.SimpleReport.LowCount++
				case model.SeverityInfo:
					previous.SimpleReport.InfoCount++
				}
			}

			current := &model.OnionScanReport{
				HiddenService: "test.onion",
				DateScanned:   time.Now(),
				SimpleReport: &model.SimpleReport{
					Findings: tt.currentFindings,
				},
			}
			// Count severities for current
			for _, f := range tt.currentFindings {
				switch f.Severity {
				case model.SeverityCritical:
					current.SimpleReport.CriticalCount++
				case model.SeverityHigh:
					current.SimpleReport.HighCount++
				case model.SeverityMedium:
					current.SimpleReport.MediumCount++
				case model.SeverityLow:
					current.SimpleReport.LowCount++
				case model.SeverityInfo:
					current.SimpleReport.InfoCount++
				}
			}

			result := compareReports(previous, current)

			if len(result.NewFindings) != tt.wantNewCount {
				t.Errorf("NewFindings count: got %d, want %d", len(result.NewFindings), tt.wantNewCount)
			}
			if len(result.ResolvedFindings) != tt.wantResolvedCount {
				t.Errorf("ResolvedFindings count: got %d, want %d", len(result.ResolvedFindings), tt.wantResolvedCount)
			}
			if result.UnchangedCount != tt.wantUnchanged {
				t.Errorf("UnchangedCount: got %d, want %d", result.UnchangedCount, tt.wantUnchanged)
			}
			if result.RiskChange.Direction != tt.wantDirection {
				t.Errorf("RiskChange.Direction: got %q, want %q", result.RiskChange.Direction, tt.wantDirection)
			}
		})
	}
}

func TestFindingKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		finding model.Finding
		want    string
	}{
		{
			name:    "generates key with all fields",
			finding: model.Finding{Type: "email", Value: "test@example.com", Location: "/page"},
			want:    "email|test@example.com|/page",
		},
		{
			name:    "handles empty location",
			finding: model.Finding{Type: "email", Value: "test@example.com"},
			want:    "email|test@example.com|",
		},
		{
			name:    "handles empty value",
			finding: model.Finding{Type: "open_directory", Location: "/uploads"},
			want:    "open_directory||/uploads",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := findingKey(tt.finding)
			if got != tt.want {
				t.Errorf("findingKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCalculateRiskChange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		previous      ScanMetadata
		current       ScanMetadata
		wantDirection string
	}{
		{
			name:          "unchanged when same",
			previous:      ScanMetadata{CriticalCount: 1, HighCount: 2},
			current:       ScanMetadata{CriticalCount: 1, HighCount: 2},
			wantDirection: "unchanged",
		},
		{
			name:          "improved when critical decreases",
			previous:      ScanMetadata{CriticalCount: 2},
			current:       ScanMetadata{CriticalCount: 1},
			wantDirection: "improved",
		},
		{
			name:          "worsened when critical increases",
			previous:      ScanMetadata{CriticalCount: 1},
			current:       ScanMetadata{CriticalCount: 2},
			wantDirection: "worsened",
		},
		{
			name:          "improved when high decreases significantly",
			previous:      ScanMetadata{HighCount: 10},
			current:       ScanMetadata{HighCount: 5},
			wantDirection: "improved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			change := calculateRiskChange(tt.previous, tt.current)
			if change.Direction != tt.wantDirection {
				t.Errorf("Direction: got %q, want %q", change.Direction, tt.wantDirection)
			}
		})
	}
}

func TestFormatRiskSummary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		summary map[string]int
		want    string
	}{
		{
			name:    "nil summary returns N/A",
			summary: nil,
			want:    "N/A",
		},
		{
			name:    "empty summary returns No findings",
			summary: map[string]int{},
			want:    "No findings",
		},
		{
			name:    "all zeros returns No findings",
			summary: map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
			want:    "No findings",
		},
		{
			name:    "formats counts correctly",
			summary: map[string]int{"critical": 1, "high": 2, "medium": 3},
			want:    "C:1 H:2 M:3",
		},
		{
			name:    "skips zero counts",
			summary: map[string]int{"critical": 0, "high": 5, "medium": 0, "low": 0, "info": 10},
			want:    "H:5 I:10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := formatRiskSummary(tt.summary)
			if got != tt.want {
				t.Errorf("formatRiskSummary() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatDelta(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		delta int
		want  string
	}{
		{name: "positive delta", delta: 5, want: "+5"},
		{name: "negative delta", delta: -3, want: "-3"},
		{name: "zero delta", delta: 0, want: "0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := formatDelta(tt.delta)
			if got != tt.want {
				t.Errorf("formatDelta(%d) = %q, want %q", tt.delta, got, tt.want)
			}
		})
	}
}

func TestFormatRiskDirection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		direction string
		want      string
	}{
		{"improved", "IMPROVED (risk decreased)"},
		{"worsened", "WORSENED (risk increased)"},
		{"unchanged", "UNCHANGED"},
		{"unknown", "UNCHANGED"},
	}

	for _, tt := range tests {
		t.Run(tt.direction, func(t *testing.T) {
			t.Parallel()

			got := formatRiskDirection(tt.direction)
			if got != tt.want {
				t.Errorf("formatRiskDirection(%q) = %q, want %q", tt.direction, got, tt.want)
			}
		})
	}
}

func TestOutputComparisonText(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	result := &ComparisonResult{
		OnionService: "test.onion",
		PreviousScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC),
			TotalFindings: 5,
			CriticalCount: 1,
			HighCount:     2,
			MediumCount:   1,
			LowCount:      1,
		},
		CurrentScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 2, 10, 0, 0, 0, time.UTC),
			TotalFindings: 4,
			CriticalCount: 0,
			HighCount:     2,
			MediumCount:   1,
			LowCount:      1,
		},
		NewFindings: []model.Finding{
			{Type: "email_address", Value: "new@example.com", SeverityText: "Medium", Title: "Email Address Found"},
		},
		ResolvedFindings: []model.Finding{
			{Type: "clearnet_ip", Value: "192.168.1.1", SeverityText: "Critical", Title: "Clearnet IP Found"},
			{Type: "email_address", Value: "old@example.com", SeverityText: "Medium", Title: "Email Address Found"},
		},
		UnchangedCount: 2,
		RiskChange: RiskChange{
			Direction:     "improved",
			CriticalDelta: -1,
		},
	}

	// Capture output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := outputComparisonText(result)

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("outputComparisonText() error = %v", err)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	// Verify key elements are present
	expectedStrings := []string{
		"test.onion",
		"IMPROVED",
		"New Findings (1)",
		"Resolved Findings (2)",
		"new@example.com",
		"192.168.1.1",
		"Unchanged: 2 findings",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("output missing expected string: %q", expected)
		}
	}
}

func TestOutputComparisonJSON(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	result := &ComparisonResult{
		OnionService: "test.onion",
		PreviousScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC),
			TotalFindings: 2,
		},
		CurrentScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 2, 10, 0, 0, 0, time.UTC),
			TotalFindings: 3,
		},
		RiskChange: RiskChange{Direction: "worsened"},
	}

	// Capture output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := outputComparisonJSON(result)

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("outputComparisonJSON() error = %v", err)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	// Verify it's valid JSON with expected fields
	if !strings.Contains(output, `"onion_service": "test.onion"`) {
		t.Error("JSON output missing onion_service field")
	}
	if !strings.Contains(output, `"direction": "worsened"`) {
		t.Error("JSON output missing risk change direction")
	}
}

func TestOutputComparisonMarkdown(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	result := &ComparisonResult{
		OnionService: "test.onion",
		PreviousScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC),
			TotalFindings: 3,
			CriticalCount: 1,
			HighCount:     1,
			MediumCount:   1,
		},
		CurrentScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 2, 10, 0, 0, 0, time.UTC),
			TotalFindings: 2,
			CriticalCount: 0,
			HighCount:     1,
			MediumCount:   1,
		},
		NewFindings: []model.Finding{
			{Type: "email_address", Value: "new@example.com", SeverityText: "Medium", Title: "Email Found", Location: "/contact"},
		},
		ResolvedFindings: []model.Finding{
			{Type: "clearnet_ip", Value: "192.168.1.1", SeverityText: "Critical", Title: "Clearnet IP Found"},
		},
		UnchangedCount: 1,
		RiskChange: RiskChange{
			Direction:     "improved",
			CriticalDelta: -1,
		},
	}

	// Capture output
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	mdErr := outputComparisonMarkdown(result)

	w.Close()
	os.Stdout = oldStdout

	if mdErr != nil {
		t.Fatalf("outputComparisonMarkdown() error = %v", mdErr)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	// Verify markdown elements
	expectedStrings := []string{
		"# Scan Comparison: test.onion",
		"## Summary",
		"**Risk Status:**",
		"| Metric | Previous | Current | Change |",
		"## New Findings (1)",
		"## Resolved Findings (1)",
		"new@example.com",
		"192.168.1.1",
		"Location: `/contact`",
		"*1 findings unchanged*",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("markdown output missing expected string: %q\nOutput: %s", expected, output)
		}
	}
}

func TestListScannedServicesIntegration(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	// Create temporary database
	tmpDir := t.TempDir()
	db, err := database.Open(tmpDir, database.DefaultOptions())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Test with empty database
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err = listScannedServices(ctx, db)

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("listScannedServices() error = %v", err)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "No scanned services found") {
		t.Error("expected 'No scanned services found' message")
	}

	// Add some data
	report := &model.OnionScanReport{
		HiddenService: "test.onion",
		DateScanned:   time.Now(),
		SimpleReport:  &model.SimpleReport{},
	}
	if err := db.SaveScanReport(ctx, report); err != nil {
		t.Fatalf("failed to save report: %v", err)
	}

	// Test with data
	r, w, _ = os.Pipe()
	os.Stdout = w

	err = listScannedServices(ctx, db)

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("listScannedServices() error = %v", err)
	}

	buf.Reset()
	_, _ = buf.ReadFrom(r)
	output = buf.String()

	if !strings.Contains(output, "test.onion") {
		t.Error("expected service to be listed")
	}
}

func TestListScanHistoryIntegration(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	// Create temporary database
	tmpDir := t.TempDir()
	db, err := database.Open(tmpDir, database.DefaultOptions())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Add test data
	for i := range 3 {
		report := &model.OnionScanReport{
			HiddenService: "test.onion",
			DateScanned:   time.Now().Add(time.Duration(-i) * time.Hour),
			SimpleReport: &model.SimpleReport{
				CriticalCount: i,
				HighCount:     i + 1,
			},
		}
		if err := db.SaveScanReport(ctx, report); err != nil {
			t.Fatalf("failed to save report: %v", err)
		}
	}

	// Test listing - capture output using pipe
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	// Run the function
	listErr := listScanHistory(ctx, db, "test.onion")

	// Close writer and restore stdout before reading
	w.Close()
	os.Stdout = oldStdout

	if listErr != nil {
		t.Fatalf("listScanHistory() error = %v", listErr)
	}

	// Read captured output
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	if !strings.Contains(output, "3 scans") {
		t.Errorf("expected '3 scans' in output, got: %s", output)
	}
	if !strings.Contains(output, "test.onion") {
		t.Errorf("expected service name in output, got: %s", output)
	}
}

func TestRunComparisonIntegration(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	// Create temporary database
	tmpDir := t.TempDir()
	db, err := database.Open(tmpDir, database.DefaultOptions())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Add two scan reports
	previousReport := &model.OnionScanReport{
		HiddenService: "test.onion",
		DateScanned:   time.Now().Add(-24 * time.Hour),
		SimpleReport: &model.SimpleReport{
			Findings: []model.Finding{
				{Type: "email_address", Value: "old@example.com", SeverityText: "Medium", Title: "Email Found"},
			},
			MediumCount: 1,
		},
	}
	currentReport := &model.OnionScanReport{
		HiddenService: "test.onion",
		DateScanned:   time.Now(),
		SimpleReport: &model.SimpleReport{
			Findings: []model.Finding{
				{Type: "email_address", Value: "new@example.com", SeverityText: "Medium", Title: "Email Found"},
			},
			MediumCount: 1,
		},
	}

	if err := db.SaveScanReport(ctx, previousReport); err != nil {
		t.Fatalf("failed to save previous report: %v", err)
	}
	if err := db.SaveScanReport(ctx, currentReport); err != nil {
		t.Fatalf("failed to save current report: %v", err)
	}

	// Test comparison - capture output using pipe
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("failed to create pipe: %v", pipeErr)
	}
	os.Stdout = w

	// Run the function
	compErr := runComparison(ctx, db, "test.onion", 0, "", false, false)

	// Close writer and restore stdout before reading
	w.Close()
	os.Stdout = oldStdout

	if compErr != nil {
		t.Fatalf("runComparison() error = %v", compErr)
	}

	// Read captured output
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	// Verify comparison output
	if !strings.Contains(output, "test.onion") {
		t.Errorf("expected service name in output, got: %s", output)
	}
	if !strings.Contains(output, "New Findings") {
		t.Errorf("expected 'New Findings' section, got: %s", output)
	}
	if !strings.Contains(output, "Resolved Findings") {
		t.Errorf("expected 'Resolved Findings' section, got: %s", output)
	}
}

func TestRunCompareCmdRequiresAddress(t *testing.T) {
	t.Parallel()

	cmd := NewCompareCmd()
	// Use --list-services with no address should work
	// But without --list-services and no address should fail
	cmd.SetArgs([]string{})

	// This test verifies the argument validation logic
	// Validation now happens before database open, so this should work reliably
	err := cmd.Execute()

	if err == nil {
		t.Error("expected error when no address provided")
	}
	if !strings.Contains(err.Error(), "onion address is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunCompareCmdInvalidAddress(t *testing.T) {
	t.Parallel()

	cmd := NewCompareCmd()
	cmd.SetArgs([]string{"invalid-address"})

	// This test verifies the address validation logic
	// Validation now happens before database open, so this should work reliably
	err := cmd.Execute()

	if err == nil {
		t.Error("expected error for invalid address")
	}
	if !strings.Contains(err.Error(), "invalid onion address") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunComparisonWithSinceDate(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	// Create temporary database
	tmpDir := t.TempDir()
	db, err := database.Open(tmpDir, database.DefaultOptions())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Add scan reports with different dates
	oldReport := &model.OnionScanReport{
		HiddenService: "test.onion",
		DateScanned:   time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC),
		SimpleReport: &model.SimpleReport{
			Findings: []model.Finding{
				{Type: "email_address", Value: "old@example.com", SeverityText: "Medium", Title: "Email Found"},
			},
			MediumCount: 1,
		},
	}
	newReport := &model.OnionScanReport{
		HiddenService: "test.onion",
		DateScanned:   time.Date(2025, 6, 1, 10, 0, 0, 0, time.UTC),
		SimpleReport: &model.SimpleReport{
			Findings: []model.Finding{
				{Type: "email_address", Value: "new@example.com", SeverityText: "Medium", Title: "Email Found"},
			},
			MediumCount: 1,
		},
	}

	if err := db.SaveScanReport(ctx, oldReport); err != nil {
		t.Fatalf("failed to save old report: %v", err)
	}
	time.Sleep(10 * time.Millisecond) // Ensure different timestamps
	if err := db.SaveScanReport(ctx, newReport); err != nil {
		t.Fatalf("failed to save new report: %v", err)
	}

	// Test comparison with --since date
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("failed to create pipe: %v", pipeErr)
	}
	os.Stdout = w

	compErr := runComparison(ctx, db, "test.onion", 0, "2025-01-01", false, false)

	w.Close()
	os.Stdout = oldStdout

	if compErr != nil {
		t.Fatalf("runComparison() error = %v", compErr)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	if !strings.Contains(output, "test.onion") {
		t.Errorf("expected service name in output, got: %s", output)
	}
}

func TestRunComparisonWithScanID(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	// Create temporary database
	tmpDir := t.TempDir()
	db, err := database.Open(tmpDir, database.DefaultOptions())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Add scan reports
	for i := range 3 {
		report := &model.OnionScanReport{
			HiddenService: "test.onion",
			DateScanned:   time.Now().Add(time.Duration(-i) * time.Hour),
			SimpleReport: &model.SimpleReport{
				Findings: []model.Finding{
					{Type: "email_address", Value: "email" + string(rune('0'+i)) + "@example.com", SeverityText: "Medium", Title: "Email Found"},
				},
				MediumCount: 1,
			},
		}
		if err := db.SaveScanReport(ctx, report); err != nil {
			t.Fatalf("failed to save report: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Get the ID of the first scan
	metadata, err := db.GetScanHistoryWithMetadata(ctx, "test.onion")
	if err != nil {
		t.Fatalf("failed to get metadata: %v", err)
	}
	if len(metadata) < 2 {
		t.Fatalf("expected at least 2 metadata records, got %d", len(metadata))
	}

	// Use the ID of an older scan for comparison
	oldScanID := metadata[len(metadata)-1].ID

	// Test comparison with --with-scan-id
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("failed to create pipe: %v", pipeErr)
	}
	os.Stdout = w

	compErr := runComparison(ctx, db, "test.onion", oldScanID, "", false, false)

	w.Close()
	os.Stdout = oldStdout

	if compErr != nil {
		t.Fatalf("runComparison() error = %v", compErr)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	if !strings.Contains(output, "test.onion") {
		t.Errorf("expected service name in output, got: %s", output)
	}
}

func TestRunComparisonWithJSONOutput(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	// Create temporary database
	tmpDir := t.TempDir()
	db, err := database.Open(tmpDir, database.DefaultOptions())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Add two scan reports
	for i := range 2 {
		report := &model.OnionScanReport{
			HiddenService: "test.onion",
			DateScanned:   time.Now().Add(time.Duration(-i) * time.Hour),
			SimpleReport:  &model.SimpleReport{MediumCount: i},
		}
		if err := db.SaveScanReport(ctx, report); err != nil {
			t.Fatalf("failed to save report: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Test comparison with JSON output
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("failed to create pipe: %v", pipeErr)
	}
	os.Stdout = w

	compErr := runComparison(ctx, db, "test.onion", 0, "", true, false)

	w.Close()
	os.Stdout = oldStdout

	if compErr != nil {
		t.Fatalf("runComparison() error = %v", compErr)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	// Verify it's valid JSON
	if !strings.Contains(output, `"onion_service": "test.onion"`) {
		t.Errorf("expected JSON with onion_service field, got: %s", output)
	}
}

func TestRunComparisonWithMarkdownOutput(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	// Create temporary database
	tmpDir := t.TempDir()
	db, err := database.Open(tmpDir, database.DefaultOptions())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Add two scan reports
	for i := range 2 {
		report := &model.OnionScanReport{
			HiddenService: "test.onion",
			DateScanned:   time.Now().Add(time.Duration(-i) * time.Hour),
			SimpleReport:  &model.SimpleReport{MediumCount: i},
		}
		if err := db.SaveScanReport(ctx, report); err != nil {
			t.Fatalf("failed to save report: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Test comparison with Markdown output
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("failed to create pipe: %v", pipeErr)
	}
	os.Stdout = w

	compErr := runComparison(ctx, db, "test.onion", 0, "", false, true)

	w.Close()
	os.Stdout = oldStdout

	if compErr != nil {
		t.Fatalf("runComparison() error = %v", compErr)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	// Verify markdown format
	if !strings.Contains(output, "# Scan Comparison: test.onion") {
		t.Errorf("expected markdown header, got: %s", output)
	}
}

func TestRunComparisonErrors(t *testing.T) {
	t.Parallel()

	// Create temporary database
	tmpDir := t.TempDir()
	db, err := database.Open(tmpDir, database.DefaultOptions())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	t.Run("returns error for non-existent service", func(t *testing.T) {
		err := runComparison(ctx, db, "nonexistent.onion", 0, "", false, false)
		if err == nil {
			t.Error("expected error for non-existent service")
		}
		if !strings.Contains(err.Error(), "no scan history found") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("returns error when only one scan exists", func(t *testing.T) {
		// Add a single scan
		report := &model.OnionScanReport{
			HiddenService: "single.onion",
			DateScanned:   time.Now(),
			SimpleReport:  &model.SimpleReport{},
		}
		if err := db.SaveScanReport(ctx, report); err != nil {
			t.Fatalf("failed to save report: %v", err)
		}

		err := runComparison(ctx, db, "single.onion", 0, "", false, false)
		if err == nil {
			t.Error("expected error when only one scan exists")
		}
		if !strings.Contains(err.Error(), "at least 2 scans are required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("returns error for non-existent scan ID", func(t *testing.T) {
		// Add two scans first
		for i := range 2 {
			report := &model.OnionScanReport{
				HiddenService: "scanid.onion",
				DateScanned:   time.Now().Add(time.Duration(-i) * time.Hour),
				SimpleReport:  &model.SimpleReport{},
			}
			if err := db.SaveScanReport(ctx, report); err != nil {
				t.Fatalf("failed to save report: %v", err)
			}
			time.Sleep(10 * time.Millisecond)
		}

		err := runComparison(ctx, db, "scanid.onion", 99999, "", false, false)
		if err == nil {
			t.Error("expected error for non-existent scan ID")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("returns error for invalid date format", func(t *testing.T) {
		// Add two scans first
		for i := range 2 {
			report := &model.OnionScanReport{
				HiddenService: "dateformat.onion",
				DateScanned:   time.Now().Add(time.Duration(-i) * time.Hour),
				SimpleReport:  &model.SimpleReport{},
			}
			if err := db.SaveScanReport(ctx, report); err != nil {
				t.Fatalf("failed to save report: %v", err)
			}
			time.Sleep(10 * time.Millisecond)
		}

		err := runComparison(ctx, db, "dateformat.onion", 0, "invalid-date", false, false)
		if err == nil {
			t.Error("expected error for invalid date format")
		}
		if !strings.Contains(err.Error(), "invalid date format") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("returns error when no scans found since date", func(t *testing.T) {
		// Add a scan with an old date
		report := &model.OnionScanReport{
			HiddenService: "futuredate.onion",
			DateScanned:   time.Date(2020, 1, 1, 10, 0, 0, 0, time.UTC),
			SimpleReport:  &model.SimpleReport{},
		}
		if err := db.SaveScanReport(ctx, report); err != nil {
			t.Fatalf("failed to save report: %v", err)
		}

		err := runComparison(ctx, db, "futuredate.onion", 0, "2030-01-01", false, false)
		if err == nil {
			t.Error("expected error when no scans found since date")
		}
		if !strings.Contains(err.Error(), "no scans found since") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("returns error when scan ID belongs to different service", func(t *testing.T) {
		// Add scans for two different services
		for _, service := range []string{"service1.onion", "service2.onion"} {
			for i := range 2 {
				report := &model.OnionScanReport{
					HiddenService: service,
					DateScanned:   time.Now().Add(time.Duration(-i) * time.Hour),
					SimpleReport:  &model.SimpleReport{},
				}
				if err := db.SaveScanReport(ctx, report); err != nil {
					t.Fatalf("failed to save report: %v", err)
				}
				time.Sleep(10 * time.Millisecond)
			}
		}

		// Get scan ID from service2
		metadata, err := db.GetScanHistoryWithMetadata(ctx, "service2.onion")
		if err != nil {
			t.Fatalf("failed to get metadata: %v", err)
		}
		if len(metadata) == 0 {
			t.Fatal("expected at least one metadata record")
		}
		service2ScanID := metadata[0].ID

		// Try to compare service1 with service2's scan ID
		err = runComparison(ctx, db, "service1.onion", service2ScanID, "", false, false)
		if err == nil {
			t.Error("expected error when scan ID belongs to different service")
		}
		if !strings.Contains(err.Error(), "belongs to") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("returns error when only one scan matches since date", func(t *testing.T) {
		// Add a single scan with a recent date
		report := &model.OnionScanReport{
			HiddenService: "singlesince.onion",
			DateScanned:   time.Date(2025, 6, 1, 10, 0, 0, 0, time.UTC),
			SimpleReport:  &model.SimpleReport{},
		}
		if err := db.SaveScanReport(ctx, report); err != nil {
			t.Fatalf("failed to save report: %v", err)
		}

		// Try to compare with --since when only one scan exists
		err := runComparison(ctx, db, "singlesince.onion", 0, "2025-01-01", false, false)
		if err == nil {
			t.Error("expected error when only one scan matches since date")
		}
		if !strings.Contains(err.Error(), "only one scan found since") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestListScanHistoryNoData(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	// Create temporary database
	tmpDir := t.TempDir()
	db, err := database.Open(tmpDir, database.DefaultOptions())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Test with empty history - capture output using pipe
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("failed to create pipe: %v", pipeErr)
	}
	os.Stdout = w

	listErr := listScanHistory(ctx, db, "nonexistent.onion")

	w.Close()
	os.Stdout = oldStdout

	if listErr != nil {
		t.Fatalf("listScanHistory() error = %v", listErr)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	if !strings.Contains(output, "No scan history found") {
		t.Errorf("expected 'No scan history found' message, got: %s", output)
	}
}

func TestCompareReportsWithNilSimpleReport(t *testing.T) {
	t.Parallel()

	t.Run("handles nil SimpleReport in previous", func(t *testing.T) {
		t.Parallel()

		previous := &model.OnionScanReport{
			HiddenService: "test.onion",
			DateScanned:   time.Now().Add(-24 * time.Hour),
			SimpleReport:  nil, // nil SimpleReport
		}
		current := &model.OnionScanReport{
			HiddenService: "test.onion",
			DateScanned:   time.Now(),
			SimpleReport: &model.SimpleReport{
				Findings: []model.Finding{
					{Type: "email_address", Value: "test@example.com", SeverityText: "Medium"},
				},
				MediumCount: 1,
			},
		}

		result := compareReports(previous, current)

		if result.OnionService != "test.onion" {
			t.Errorf("expected OnionService 'test.onion', got %q", result.OnionService)
		}
		if len(result.NewFindings) != 1 {
			t.Errorf("expected 1 new finding, got %d", len(result.NewFindings))
		}
		if result.PreviousScan.TotalFindings != 0 {
			t.Errorf("expected 0 previous findings, got %d", result.PreviousScan.TotalFindings)
		}
	})

	t.Run("handles nil SimpleReport in current", func(t *testing.T) {
		t.Parallel()

		previous := &model.OnionScanReport{
			HiddenService: "test.onion",
			DateScanned:   time.Now().Add(-24 * time.Hour),
			SimpleReport: &model.SimpleReport{
				Findings: []model.Finding{
					{Type: "email_address", Value: "test@example.com", SeverityText: "Medium"},
				},
				MediumCount: 1,
			},
		}
		current := &model.OnionScanReport{
			HiddenService: "test.onion",
			DateScanned:   time.Now(),
			SimpleReport:  nil, // nil SimpleReport
		}

		result := compareReports(previous, current)

		if len(result.ResolvedFindings) != 1 {
			t.Errorf("expected 1 resolved finding, got %d", len(result.ResolvedFindings))
		}
		if result.CurrentScan.TotalFindings != 0 {
			t.Errorf("expected 0 current findings, got %d", result.CurrentScan.TotalFindings)
		}
	})

	t.Run("handles nil SimpleReport in both", func(t *testing.T) {
		t.Parallel()

		previous := &model.OnionScanReport{
			HiddenService: "test.onion",
			DateScanned:   time.Now().Add(-24 * time.Hour),
			SimpleReport:  nil,
		}
		current := &model.OnionScanReport{
			HiddenService: "test.onion",
			DateScanned:   time.Now(),
			SimpleReport:  nil,
		}

		result := compareReports(previous, current)

		if len(result.NewFindings) != 0 {
			t.Errorf("expected 0 new findings, got %d", len(result.NewFindings))
		}
		if len(result.ResolvedFindings) != 0 {
			t.Errorf("expected 0 resolved findings, got %d", len(result.ResolvedFindings))
		}
		if result.RiskChange.Direction != "unchanged" {
			t.Errorf("expected direction 'unchanged', got %q", result.RiskChange.Direction)
		}
	})
}

func TestListScannedServicesWithData(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	// Create temporary database
	tmpDir := t.TempDir()
	db, err := database.Open(tmpDir, database.DefaultOptions())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Add multiple services
	for _, service := range []string{"service1.onion", "service2.onion", "service3.onion"} {
		report := &model.OnionScanReport{
			HiddenService: service,
			DateScanned:   time.Now(),
			SimpleReport:  &model.SimpleReport{},
		}
		if err := db.SaveScanReport(ctx, report); err != nil {
			t.Fatalf("failed to save report: %v", err)
		}
	}

	// Test listing with data
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("failed to create pipe: %v", pipeErr)
	}
	os.Stdout = w

	listErr := listScannedServices(ctx, db)

	w.Close()
	os.Stdout = oldStdout

	if listErr != nil {
		t.Fatalf("listScannedServices() error = %v", listErr)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	if !strings.Contains(output, "service1.onion") {
		t.Error("expected service1.onion in output")
	}
	if !strings.Contains(output, "service2.onion") {
		t.Error("expected service2.onion in output")
	}
	if !strings.Contains(output, "Scanned services (3)") {
		t.Errorf("expected 'Scanned services (3)' in output, got: %s", output)
	}
}

func TestCalculateRiskChangeAllSeverities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		previous      ScanMetadata
		current       ScanMetadata
		wantDirection string
	}{
		{
			name:          "worsened when medium increases",
			previous:      ScanMetadata{MediumCount: 5},
			current:       ScanMetadata{MediumCount: 10},
			wantDirection: "worsened",
		},
		{
			name:          "improved when medium decreases",
			previous:      ScanMetadata{MediumCount: 10},
			current:       ScanMetadata{MediumCount: 5},
			wantDirection: "improved",
		},
		{
			name:          "worsened when low increases",
			previous:      ScanMetadata{LowCount: 0},
			current:       ScanMetadata{LowCount: 10},
			wantDirection: "worsened",
		},
		{
			name:          "worsened when info increases significantly",
			previous:      ScanMetadata{InfoCount: 0},
			current:       ScanMetadata{InfoCount: 100},
			wantDirection: "worsened",
		},
		{
			name: "critical increase causes worsened despite other improvements",
			previous: ScanMetadata{
				CriticalCount: 0,
				HighCount:     1,
				MediumCount:   1,
			},
			current: ScanMetadata{
				CriticalCount: 2,
				HighCount:     0,
				MediumCount:   0,
			},
			// previous = 0*100 + 1*50 + 1*10 = 60
			// current = 2*100 + 0 + 0 = 200
			// 200 > 60, so worsened
			wantDirection: "worsened",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			change := calculateRiskChange(tt.previous, tt.current)
			if change.Direction != tt.wantDirection {
				t.Errorf("Direction: got %q, want %q", change.Direction, tt.wantDirection)
			}
		})
	}
}

func TestOutputComparisonTextWithLocation(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	result := &ComparisonResult{
		OnionService: "test.onion",
		PreviousScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC),
			TotalFindings: 1,
		},
		CurrentScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 2, 10, 0, 0, 0, time.UTC),
			TotalFindings: 1,
		},
		NewFindings: []model.Finding{
			{Type: "email_address", Value: "new@example.com", SeverityText: "Medium", Title: "Email Found", Location: "/contact.html"},
		},
		RiskChange: RiskChange{Direction: "worsened"},
	}

	// Capture output
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("failed to create pipe: %v", pipeErr)
	}
	os.Stdout = w

	err := outputComparisonText(result)

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("outputComparisonText() error = %v", err)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	// Verify location is included
	if !strings.Contains(output, "/contact.html") {
		t.Error("expected location to be included in output")
	}
	if !strings.Contains(output, "Location:") {
		t.Error("expected 'Location:' label in output")
	}
}

func TestFormatRiskSummaryAllSeverities(t *testing.T) {
	t.Parallel()

	t.Run("formats low count", func(t *testing.T) {
		t.Parallel()

		summary := map[string]int{"low": 5}
		result := formatRiskSummary(summary)
		if result != "L:5" {
			t.Errorf("expected 'L:5', got %q", result)
		}
	})

	t.Run("formats info count", func(t *testing.T) {
		t.Parallel()

		summary := map[string]int{"info": 10}
		result := formatRiskSummary(summary)
		if result != "I:10" {
			t.Errorf("expected 'I:10', got %q", result)
		}
	})

	t.Run("formats all severity levels", func(t *testing.T) {
		t.Parallel()

		summary := map[string]int{
			"critical": 1,
			"high":     2,
			"medium":   3,
			"low":      4,
			"info":     5,
		}
		result := formatRiskSummary(summary)
		if result != "C:1 H:2 M:3 L:4 I:5" {
			t.Errorf("expected 'C:1 H:2 M:3 L:4 I:5', got %q", result)
		}
	})
}

func TestOutputComparisonMarkdownAllPaths(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	// Test with no new findings but has resolved findings
	result := &ComparisonResult{
		OnionService: "test.onion",
		PreviousScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC),
			TotalFindings: 2,
			CriticalCount: 1,
			HighCount:     1,
		},
		CurrentScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 2, 10, 0, 0, 0, time.UTC),
			TotalFindings: 0,
		},
		NewFindings: nil,
		ResolvedFindings: []model.Finding{
			{Type: "clearnet_ip", Value: "192.168.1.1", SeverityText: "Critical", Title: "Clearnet IP Found"},
			{Type: "email_address", Value: "old@example.com", SeverityText: "High", Title: "Email Found"},
		},
		UnchangedCount: 0,
		RiskChange:     RiskChange{Direction: "improved", CriticalDelta: -1, HighDelta: -1},
	}

	// Capture output
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("failed to create pipe: %v", pipeErr)
	}
	os.Stdout = w

	err := outputComparisonMarkdown(result)

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("outputComparisonMarkdown() error = %v", err)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	// Verify resolved findings are shown with strikethrough
	if !strings.Contains(output, "~~**[Critical]**") {
		t.Error("expected resolved findings with strikethrough in output")
	}
	if !strings.Contains(output, "## Resolved Findings (2)") {
		t.Error("expected resolved findings section header")
	}
	// Should not have "unchanged" section since count is 0
	if strings.Contains(output, "unchanged") {
		t.Error("did not expect 'unchanged' text when count is 0")
	}
}

func TestOutputComparisonTextAllPaths(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	// Test with all severity deltas
	result := &ComparisonResult{
		OnionService: "test.onion",
		PreviousScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC),
			TotalFindings: 10,
			CriticalCount: 2,
			HighCount:     3,
			MediumCount:   2,
			LowCount:      2,
			InfoCount:     1,
		},
		CurrentScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 2, 10, 0, 0, 0, time.UTC),
			TotalFindings: 5,
			CriticalCount: 1,
			HighCount:     1,
			MediumCount:   1,
			LowCount:      1,
			InfoCount:     1,
		},
		NewFindings: nil,
		ResolvedFindings: []model.Finding{
			{Type: "clearnet_ip", Value: "192.168.1.1", SeverityText: "Critical", Title: "Clearnet IP"},
		},
		UnchangedCount: 4,
		RiskChange: RiskChange{
			Direction:     "improved",
			CriticalDelta: -1,
			HighDelta:     -2,
			MediumDelta:   -1,
			LowDelta:      -1,
			InfoDelta:     0,
		},
	}

	// Capture output
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("failed to create pipe: %v", pipeErr)
	}
	os.Stdout = w

	err := outputComparisonText(result)

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("outputComparisonText() error = %v", err)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	// Verify all severity levels are displayed
	expectedStrings := []string{
		"Critical",
		"High",
		"Medium",
		"Low",
		"Info",
		"Total",
		"IMPROVED",
		"-1", // negative delta
		"-2", // negative delta for high
		"Resolved Findings (1)",
		"Unchanged: 4 findings",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("expected %q in output, got: %s", expected, output)
		}
	}
}

func TestCalculateRiskChangeDeltas(t *testing.T) {
	t.Parallel()

	t.Run("calculates all deltas correctly", func(t *testing.T) {
		t.Parallel()

		previous := ScanMetadata{
			CriticalCount: 5,
			HighCount:     4,
			MediumCount:   3,
			LowCount:      2,
			InfoCount:     1,
		}
		current := ScanMetadata{
			CriticalCount: 2,
			HighCount:     6,
			MediumCount:   1,
			LowCount:      4,
			InfoCount:     3,
		}

		change := calculateRiskChange(previous, current)

		if change.CriticalDelta != -3 {
			t.Errorf("CriticalDelta: got %d, want -3", change.CriticalDelta)
		}
		if change.HighDelta != 2 {
			t.Errorf("HighDelta: got %d, want 2", change.HighDelta)
		}
		if change.MediumDelta != -2 {
			t.Errorf("MediumDelta: got %d, want -2", change.MediumDelta)
		}
		if change.LowDelta != 2 {
			t.Errorf("LowDelta: got %d, want 2", change.LowDelta)
		}
		if change.InfoDelta != 2 {
			t.Errorf("InfoDelta: got %d, want 2", change.InfoDelta)
		}
	})
}

func TestOutputComparisonMarkdownNoNewOrResolved(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	// Test with unchanged findings only
	result := &ComparisonResult{
		OnionService: "test.onion",
		PreviousScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC),
			TotalFindings: 5,
			MediumCount:   5,
		},
		CurrentScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 2, 10, 0, 0, 0, time.UTC),
			TotalFindings: 5,
			MediumCount:   5,
		},
		NewFindings:      nil,
		ResolvedFindings: nil,
		UnchangedCount:   5,
		RiskChange:       RiskChange{Direction: "unchanged"},
	}

	// Capture output
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("failed to create pipe: %v", pipeErr)
	}
	os.Stdout = w

	err := outputComparisonMarkdown(result)

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("outputComparisonMarkdown() error = %v", err)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	// Should not have New Findings or Resolved Findings sections
	if strings.Contains(output, "## New Findings") {
		t.Error("did not expect 'New Findings' section when there are none")
	}
	if strings.Contains(output, "## Resolved Findings") {
		t.Error("did not expect 'Resolved Findings' section when there are none")
	}
	// Should have unchanged count
	if !strings.Contains(output, "*5 findings unchanged*") {
		t.Errorf("expected unchanged count, got: %s", output)
	}
}

func TestOutputComparisonTextNoFindingsChanges(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	// Test with no new or resolved findings
	result := &ComparisonResult{
		OnionService: "test.onion",
		PreviousScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC),
			TotalFindings: 3,
		},
		CurrentScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 2, 10, 0, 0, 0, time.UTC),
			TotalFindings: 3,
		},
		NewFindings:      nil,
		ResolvedFindings: nil,
		UnchangedCount:   0,
		RiskChange:       RiskChange{Direction: "unchanged"},
	}

	// Capture output
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("failed to create pipe: %v", pipeErr)
	}
	os.Stdout = w

	err := outputComparisonText(result)

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("outputComparisonText() error = %v", err)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	// Should not contain New Findings or Resolved Findings sections
	if strings.Contains(output, "New Findings") {
		t.Error("did not expect 'New Findings' section")
	}
	if strings.Contains(output, "Resolved Findings") {
		t.Error("did not expect 'Resolved Findings' section")
	}
	// Should not contain Unchanged message when count is 0
	if strings.Contains(output, "Unchanged:") {
		t.Error("did not expect 'Unchanged:' message when count is 0")
	}
}

func TestListScanHistoryWithData(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	// Create temporary database
	tmpDir := t.TempDir()
	db, err := database.Open(tmpDir, database.DefaultOptions())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Add multiple scans for the same service
	for i := range 3 {
		report := &model.OnionScanReport{
			HiddenService: "history.onion",
			DateScanned:   time.Now().Add(time.Duration(-i) * time.Hour),
			SimpleReport: &model.SimpleReport{
				CriticalCount: i,
				HighCount:     i + 1,
				MediumCount:   i + 2,
			},
		}
		if err := db.SaveScanReport(ctx, report); err != nil {
			t.Fatalf("failed to save report: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Capture output
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("failed to create pipe: %v", pipeErr)
	}
	os.Stdout = w

	listErr := listScanHistory(ctx, db, "history.onion")

	w.Close()
	os.Stdout = oldStdout

	if listErr != nil {
		t.Fatalf("listScanHistory() error = %v", listErr)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	// Verify output contains expected elements
	if !strings.Contains(output, "history.onion") {
		t.Error("expected service name in output")
	}
	if !strings.Contains(output, "Scan history for") {
		t.Error("expected 'Scan history for' header in output")
	}
	if !strings.Contains(output, "ID") {
		t.Error("expected 'ID' column header in output")
	}
}

func TestOutputComparisonJSONWithFindings(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	result := &ComparisonResult{
		OnionService: "json-test.onion",
		PreviousScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC),
			TotalFindings: 2,
			CriticalCount: 1,
			HighCount:     1,
		},
		CurrentScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 2, 10, 0, 0, 0, time.UTC),
			TotalFindings: 3,
			CriticalCount: 1,
			HighCount:     2,
		},
		NewFindings: []model.Finding{
			{Type: "email_address", Value: "new@example.com", SeverityText: "High", Title: "Email Found"},
		},
		ResolvedFindings: []model.Finding{},
		UnchangedCount:   2,
		RiskChange: RiskChange{
			Direction: "worsened",
			HighDelta: 1,
		},
	}

	// Capture output
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("failed to create pipe: %v", pipeErr)
	}
	os.Stdout = w

	err := outputComparisonJSON(result)

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("outputComparisonJSON() error = %v", err)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	// Verify JSON output contains expected fields
	expectedFields := []string{
		`"onion_service": "json-test.onion"`,
		`"direction": "worsened"`,
		`"new_findings"`,
		`"unchanged_count": 2`,
	}
	for _, field := range expectedFields {
		if !strings.Contains(output, field) {
			t.Errorf("expected JSON to contain %q, got: %s", field, output)
		}
	}
}

func TestFormatRiskSummaryNilAndEmpty(t *testing.T) {
	t.Parallel()

	t.Run("returns N/A for nil summary", func(t *testing.T) {
		t.Parallel()
		result := formatRiskSummary(nil)
		if result != "N/A" {
			t.Errorf("expected 'N/A', got %q", result)
		}
	})

	t.Run("returns No findings for empty summary", func(t *testing.T) {
		t.Parallel()
		result := formatRiskSummary(map[string]int{})
		if result != "No findings" {
			t.Errorf("expected 'No findings', got %q", result)
		}
	})

	t.Run("returns No findings for all zeros", func(t *testing.T) {
		t.Parallel()
		summary := map[string]int{
			"critical": 0,
			"high":     0,
			"medium":   0,
			"low":      0,
			"info":     0,
		}
		result := formatRiskSummary(summary)
		if result != "No findings" {
			t.Errorf("expected 'No findings', got %q", result)
		}
	})
}

func TestOutputComparisonMarkdownWithNewFindings(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	result := &ComparisonResult{
		OnionService: "markdown.onion",
		PreviousScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC),
			TotalFindings: 1,
			MediumCount:   1,
		},
		CurrentScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 2, 10, 0, 0, 0, time.UTC),
			TotalFindings: 3,
			CriticalCount: 1,
			HighCount:     1,
			MediumCount:   1,
		},
		NewFindings: []model.Finding{
			{Type: "clearnet_ip", Value: "1.2.3.4", SeverityText: "Critical", Title: "Clearnet IP Found", Location: "/config"},
			{Type: "email_address", Value: "admin@example.com", SeverityText: "High", Title: "Email Found"},
		},
		ResolvedFindings: nil,
		UnchangedCount:   1,
		RiskChange: RiskChange{
			Direction:     "worsened",
			CriticalDelta: 1,
			HighDelta:     1,
		},
	}

	// Capture output
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("failed to create pipe: %v", pipeErr)
	}
	os.Stdout = w

	err := outputComparisonMarkdown(result)

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("outputComparisonMarkdown() error = %v", err)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	// Verify markdown output contains expected elements
	expectedStrings := []string{
		"# Scan Comparison: markdown.onion",
		"## New Findings (2)",
		"**[Critical]**",
		"**[High]**",
		"*1 findings unchanged*",
		"WORSENED",
	}
	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("expected markdown to contain %q, got: %s", expected, output)
		}
	}
}

func TestCompareReportsWithMixedSeverities(t *testing.T) {
	t.Parallel()

	previous := &model.OnionScanReport{
		HiddenService: "test.onion",
		DateScanned:   time.Now().Add(-24 * time.Hour),
		SimpleReport: &model.SimpleReport{
			Findings: []model.Finding{
				{Type: "email_address", Value: "keep@example.com", Severity: model.SeverityMedium, SeverityText: "Medium"},
				{Type: "analytics_id", Value: "GA-123", Severity: model.SeverityHigh, SeverityText: "High"},
			},
			MediumCount: 1,
			HighCount:   1,
		},
	}
	current := &model.OnionScanReport{
		HiddenService: "test.onion",
		DateScanned:   time.Now(),
		SimpleReport: &model.SimpleReport{
			Findings: []model.Finding{
				{Type: "email_address", Value: "keep@example.com", Severity: model.SeverityMedium, SeverityText: "Medium"},
				{Type: "clearnet_ip", Value: "10.0.0.1", Severity: model.SeverityCritical, SeverityText: "Critical"},
				{Type: "social_link", Value: "twitter.com/user", Severity: model.SeverityLow, SeverityText: "Low"},
			},
			MediumCount:   1,
			CriticalCount: 1,
			LowCount:      1,
		},
	}

	result := compareReports(previous, current)

	if result.OnionService != "test.onion" {
		t.Errorf("expected OnionService 'test.onion', got %q", result.OnionService)
	}
	if len(result.NewFindings) != 2 {
		t.Errorf("expected 2 new findings, got %d", len(result.NewFindings))
	}
	if len(result.ResolvedFindings) != 1 {
		t.Errorf("expected 1 resolved finding, got %d", len(result.ResolvedFindings))
	}
	if result.UnchangedCount != 1 {
		t.Errorf("expected 1 unchanged, got %d", result.UnchangedCount)
	}
	// Critical increased, so should be worsened
	if result.RiskChange.Direction != "worsened" {
		t.Errorf("expected direction 'worsened', got %q", result.RiskChange.Direction)
	}
	if result.RiskChange.CriticalDelta != 1 {
		t.Errorf("expected CriticalDelta 1, got %d", result.RiskChange.CriticalDelta)
	}
}

func TestListScannedServicesEmpty(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	// Create temporary database
	tmpDir := t.TempDir()
	db, err := database.Open(tmpDir, database.DefaultOptions())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Capture output - empty database
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("failed to create pipe: %v", pipeErr)
	}
	os.Stdout = w

	listErr := listScannedServices(ctx, db)

	w.Close()
	os.Stdout = oldStdout

	if listErr != nil {
		t.Fatalf("listScannedServices() error = %v", listErr)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	if !strings.Contains(output, "No scanned services found") {
		t.Errorf("expected 'No scanned services found' message, got: %s", output)
	}
}

func TestRunComparisonSuccessful(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	// Create temporary database
	tmpDir := t.TempDir()
	db, err := database.Open(tmpDir, database.DefaultOptions())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Add two different scan reports
	report1 := &model.OnionScanReport{
		HiddenService: "success.onion",
		DateScanned:   time.Now().Add(-2 * time.Hour),
		SimpleReport: &model.SimpleReport{
			Findings: []model.Finding{
				{Type: "email_address", Value: "old@example.com", SeverityText: "Medium"},
			},
			MediumCount: 1,
		},
	}
	report2 := &model.OnionScanReport{
		HiddenService: "success.onion",
		DateScanned:   time.Now(),
		SimpleReport: &model.SimpleReport{
			Findings: []model.Finding{
				{Type: "email_address", Value: "new@example.com", SeverityText: "Medium"},
			},
			MediumCount: 1,
		},
	}

	if err := db.SaveScanReport(ctx, report1); err != nil {
		t.Fatalf("failed to save report1: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := db.SaveScanReport(ctx, report2); err != nil {
		t.Fatalf("failed to save report2: %v", err)
	}

	// Capture output
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("failed to create pipe: %v", pipeErr)
	}
	os.Stdout = w

	compErr := runComparison(ctx, db, "success.onion", 0, "", false, false)

	w.Close()
	os.Stdout = oldStdout

	if compErr != nil {
		t.Fatalf("runComparison() error = %v", compErr)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	// Verify comparison output
	if !strings.Contains(output, "success.onion") {
		t.Errorf("expected service name in output, got: %s", output)
	}
	if !strings.Contains(output, "Scan Comparison") {
		t.Errorf("expected 'Scan Comparison' in output, got: %s", output)
	}
}

func TestFormatDeltaAllCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		delta int
		want  string
	}{
		{"positive large", 100, "+100"},
		{"positive small", 1, "+1"},
		{"zero", 0, "0"},
		{"negative small", -1, "-1"},
		{"negative large", -100, "-100"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatDelta(tt.delta)
			if got != tt.want {
				t.Errorf("formatDelta(%d) = %q, want %q", tt.delta, got, tt.want)
			}
		})
	}
}

func TestFormatRiskDirectionAllCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		direction string
		want      string
	}{
		{"improved", "IMPROVED (risk decreased)"},
		{"worsened", "WORSENED (risk increased)"},
		{"unchanged", "UNCHANGED"},
		{"unknown", "UNCHANGED"},
		{"other", "UNCHANGED"},
	}

	for _, tt := range tests {
		t.Run(tt.direction, func(t *testing.T) {
			t.Parallel()
			got := formatRiskDirection(tt.direction)
			if got != tt.want {
				t.Errorf("formatRiskDirection(%q) = %q, want %q", tt.direction, got, tt.want)
			}
		})
	}
}

func TestOutputComparisonTextWithResolvedFindings(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	result := &ComparisonResult{
		OnionService: "resolved.onion",
		PreviousScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC),
			TotalFindings: 3,
			CriticalCount: 1,
			HighCount:     2,
		},
		CurrentScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 2, 10, 0, 0, 0, time.UTC),
			TotalFindings: 0,
		},
		NewFindings: nil,
		ResolvedFindings: []model.Finding{
			{Type: "clearnet_ip", Value: "192.168.1.1", SeverityText: "Critical", Title: "Clearnet IP Found"},
			{Type: "analytics_id", Value: "GA-123", SeverityText: "High", Title: "Analytics ID"},
			{Type: "email_address", Value: "test@example.com", SeverityText: "High", Title: "Email Found", Location: "/contact"},
		},
		UnchangedCount: 0,
		RiskChange: RiskChange{
			Direction:     "improved",
			CriticalDelta: -1,
			HighDelta:     -2,
		},
	}

	// Capture output
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("failed to create pipe: %v", pipeErr)
	}
	os.Stdout = w

	err := outputComparisonText(result)

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("outputComparisonText() error = %v", err)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	// Verify resolved findings section
	expectedStrings := []string{
		"Resolved Findings (3)",
		"IMPROVED",
		"Critical",
		"-1",
		"-2",
	}
	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("expected %q in output, got: %s", expected, output)
		}
	}
}

func TestOutputComparisonMarkdownWithResolvedFindings(t *testing.T) {
	// Note: Not using t.Parallel() because this test captures os.Stdout

	result := &ComparisonResult{
		OnionService: "resolved.onion",
		PreviousScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC),
			TotalFindings: 2,
			HighCount:     2,
		},
		CurrentScan: ScanMetadata{
			DateScanned:   time.Date(2025, 1, 2, 10, 0, 0, 0, time.UTC),
			TotalFindings: 0,
		},
		NewFindings: nil,
		ResolvedFindings: []model.Finding{
			{Type: "email_address", Value: "old@example.com", SeverityText: "High", Title: "Email Found"},
			{Type: "analytics_id", Value: "GA-456", SeverityText: "High", Title: "Analytics ID", Location: "/page.html"},
		},
		UnchangedCount: 0,
		RiskChange: RiskChange{
			Direction: "improved",
			HighDelta: -2,
		},
	}

	// Capture output
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("failed to create pipe: %v", pipeErr)
	}
	os.Stdout = w

	err := outputComparisonMarkdown(result)

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("outputComparisonMarkdown() error = %v", err)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	// Verify resolved findings with strikethrough
	expectedStrings := []string{
		"## Resolved Findings (2)",
		"~~**[High]**",
		"IMPROVED",
	}
	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("expected markdown to contain %q, got: %s", expected, output)
		}
	}
}

// Note: Tests for runCompareCmd with full execution (TestRunCompareCmdWithListServices,
// TestRunCompareCmdWithListHistory, TestRunCompareCmdNoArgsWithXDG, TestRunCompareCmdInvalidAddressWithXDG,
// TestRunCompareCmdWithComparison, TestRunCompareCmdWithJSONOutput, TestRunCompareCmdWithMarkdownOutput,
// TestRunCompareCmdWithScanID, TestRunCompareCmdWithSinceDate) are not included because:
//
// The xdg library (adrg/xdg) caches the XDG_DATA_HOME value at package initialization time,
// not at runtime. This means t.Setenv("XDG_DATA_HOME", tmpDir) has no effect since the xdg
// package has already read the environment variable before the test runs.
//
// Possible solutions:
// 1. Modify xdg.DataHome directly - but this breaks parallel test execution (t.Parallel())
// 2. Refactor code to accept database path as a parameter - requires significant code changes
// 3. Use integration tests with real XDG directory - but this affects real user data
//
// For now, the runCompareCmd function is tested through:
// - Unit tests for helper functions (compareReports, formatOutput, etc.)
// - Manual integration testing
