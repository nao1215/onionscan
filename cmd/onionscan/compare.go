package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nao1215/onionscan/internal/config"
	"github.com/nao1215/onionscan/internal/database"
	"github.com/nao1215/onionscan/internal/model"
	"github.com/nao1215/onionscan/internal/tor"
	"github.com/spf13/cobra"
)

// Constants for risk direction and summary messages.
const (
	riskDirectionWorsened  = "worsened"
	riskDirectionImproved  = "improved"
	riskDirectionUnchanged = "unchanged"
	noFindingsMessage      = "No findings"
)

// NewCompareCmd creates the compare command.
// This command compares scan results with historical data stored in the database.
func NewCompareCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compare [onion-address]",
		Short: "Compare scan results with historical data",
		Long: `Compare displays differences between the current and previous scan results.

This command retrieves historical scan data from the database and shows:
- New findings that appeared since the last scan
- Resolved findings that are no longer present
- Changes in risk severity levels

The comparison requires at least two scans in the database for the specified
onion address. Use 'onionscan scan' to perform scans and save results.

Examples:
  # Compare latest two scans for a service
  onionscan compare exampleonion.onion

  # List all scan history for a service
  onionscan compare --list exampleonion.onion

  # Compare with a specific historical scan by ID
  onionscan compare --with-scan-id 5 exampleonion.onion

  # Compare scans since a specific date
  onionscan compare --since "2025-01-01" exampleonion.onion

  # Output comparison in JSON format
  onionscan compare --json exampleonion.onion

  # List all scanned services in the database
  onionscan compare --list-services`,
		Args: cobra.MaximumNArgs(1),
		RunE: runCompareCmd,
	}

	// History listing flags
	cmd.Flags().BoolP("list", "l", false,
		"List scan history for the specified onion address")
	cmd.Flags().BoolP("list-services", "L", false,
		"List all scanned services in the database")

	// Comparison target flags
	cmd.Flags().Int64P("with-scan-id", "i", 0,
		"Compare with a specific scan by ID (use --list to see available IDs)")
	cmd.Flags().StringP("since", "s", "",
		"Compare with the first scan after this date (format: YYYY-MM-DD)")

	// Output format flags
	cmd.Flags().BoolP("json", "j", false,
		"Output comparison result in JSON format")
	cmd.Flags().BoolP("markdown", "m", false,
		"Output comparison result in Markdown format")

	return cmd
}

// runCompareCmd executes the compare command.
func runCompareCmd(cmd *cobra.Command, args []string) error {
	// Handle --list-services flag first (requires database but no address)
	listServices, err := cmd.Flags().GetBool("list-services")
	if err != nil {
		return err
	}

	// Validate arguments before opening database (unless --list-services)
	// This prevents database lock issues when validation fails
	var onionAddr string
	if !listServices {
		// Require an onion address for other operations
		if len(args) == 0 {
			return errors.New("onion address is required (use --list-services to see available services)")
		}

		// Normalize the onion address
		onionAddr, err = tor.NormalizeAddress(args[0])
		if err != nil {
			return fmt.Errorf("invalid onion address: %w", err)
		}
	}

	// Use XDG data directory for database
	dbDir := config.XDGDataDir()

	// Open database
	db, err := database.Open(dbDir, database.DefaultOptions())
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Handle --list-services flag
	if listServices {
		return listScannedServices(ctx, db)
	}

	// Handle --list flag
	listHistory, err := cmd.Flags().GetBool("list")
	if err != nil {
		return err
	}
	if listHistory {
		return listScanHistory(ctx, db, onionAddr)
	}

	// Get output format flags
	jsonOutput, err := cmd.Flags().GetBool("json")
	if err != nil {
		return err
	}
	markdownOutput, err := cmd.Flags().GetBool("markdown")
	if err != nil {
		return err
	}

	// Get comparison target flags
	withScanID, err := cmd.Flags().GetInt64("with-scan-id")
	if err != nil {
		return err
	}
	sinceDate, err := cmd.Flags().GetString("since")
	if err != nil {
		return err
	}

	// Perform comparison
	return runComparison(ctx, db, onionAddr, withScanID, sinceDate, jsonOutput, markdownOutput)
}

// listScannedServices lists all services that have scan records in the database.
func listScannedServices(ctx context.Context, db *database.CrawlDB) error {
	services, err := db.ListScannedServices(ctx)
	if err != nil {
		return fmt.Errorf("failed to list services: %w", err)
	}

	if len(services) == 0 {
		fmt.Println("No scanned services found in the database.")
		fmt.Println("\nUse 'onionscan scan <address>' to scan a hidden service.")
		return nil
	}

	fmt.Printf("Scanned services (%d):\n\n", len(services))
	for _, service := range services {
		fmt.Printf("  • %s\n", service)
	}
	fmt.Println("\nUse 'onionscan compare --list <address>' to see scan history for a service.")

	return nil
}

// listScanHistory lists all scan records for a specific onion address.
func listScanHistory(ctx context.Context, db *database.CrawlDB, onionAddr string) error {
	reports, err := db.GetScanHistoryWithMetadata(ctx, onionAddr)
	if err != nil {
		return fmt.Errorf("failed to get scan history: %w", err)
	}

	if len(reports) == 0 {
		fmt.Printf("No scan history found for %s\n", onionAddr)
		fmt.Println("\nUse 'onionscan scan' to scan this service.")
		return nil
	}

	fmt.Printf("Scan history for %s (%d scans):\n\n", onionAddr, len(reports))
	fmt.Printf("  %-6s  %-20s  %s\n", "ID", "Date", "Risk Summary")
	fmt.Println("  " + strings.Repeat("-", 60))

	for _, meta := range reports {
		riskSummary := formatRiskSummary(meta.RiskSummary)
		fmt.Printf("  %-6d  %-20s  %s\n",
			meta.ID,
			meta.Timestamp.Format("2006-01-02 15:04:05"),
			riskSummary,
		)
	}

	fmt.Println("\nUse 'onionscan compare <address>' to compare the latest two scans.")
	fmt.Println("Use 'onionscan compare --with-scan-id <id> <address>' to compare with a specific scan.")

	return nil
}

// formatRiskSummary formats the risk summary map into a human-readable string.
func formatRiskSummary(summary map[string]int) string {
	if summary == nil {
		return "N/A"
	}

	var parts []string
	if v := summary["critical"]; v > 0 {
		parts = append(parts, fmt.Sprintf("C:%d", v))
	}
	if v := summary["high"]; v > 0 {
		parts = append(parts, fmt.Sprintf("H:%d", v))
	}
	if v := summary["medium"]; v > 0 {
		parts = append(parts, fmt.Sprintf("M:%d", v))
	}
	if v := summary["low"]; v > 0 {
		parts = append(parts, fmt.Sprintf("L:%d", v))
	}
	if v := summary["info"]; v > 0 {
		parts = append(parts, fmt.Sprintf("I:%d", v))
	}

	if len(parts) == 0 {
		return noFindingsMessage
	}
	return strings.Join(parts, " ")
}

// runComparison performs the actual comparison between scan reports.
func runComparison(ctx context.Context, db *database.CrawlDB, onionAddr string, withScanID int64, sinceDate string, jsonOutput, markdownOutput bool) error {
	// Get the scan history
	reports, err := db.GetScanHistory(ctx, onionAddr)
	if err != nil {
		return fmt.Errorf("failed to get scan history: %w", err)
	}

	if len(reports) == 0 {
		return fmt.Errorf("no scan history found for %s", onionAddr)
	}

	if len(reports) < 2 && withScanID == 0 && sinceDate == "" {
		return fmt.Errorf("at least 2 scans are required for comparison (found %d)", len(reports))
	}

	// Determine which reports to compare
	var currentReport, previousReport *model.OnionScanReport

	// Latest report is always the current one
	currentReport = reports[0]

	if withScanID > 0 {
		// Find the report with the specified ID
		previousReport, err = db.GetScanReportByID(ctx, withScanID)
		if err != nil {
			return fmt.Errorf("failed to get scan with ID %d: %w", withScanID, err)
		}
		if previousReport == nil {
			return fmt.Errorf("scan with ID %d not found", withScanID)
		}
		// Validate that the scan ID belongs to the same service
		if previousReport.HiddenService != onionAddr {
			return fmt.Errorf("scan ID %d belongs to %s, not %s", withScanID, previousReport.HiddenService, onionAddr)
		}
	} else if sinceDate != "" {
		// Parse the date and find the first (oldest) report at or after the specified date
		parsedDate, err := time.Parse("2006-01-02", sinceDate)
		if err != nil {
			return fmt.Errorf("invalid date format (use YYYY-MM-DD): %w", err)
		}

		// Reports are sorted by timestamp DESC (newest first), so iterate in reverse
		// to find the first (oldest) report at or after the date
		for i := len(reports) - 1; i >= 0; i-- {
			r := reports[i]
			if r.DateScanned.After(parsedDate) || r.DateScanned.Equal(parsedDate) {
				previousReport = r
				break // Stop at the first (oldest) matching report
			}
		}
		if previousReport == nil {
			return fmt.Errorf("no scans found since %s", sinceDate)
		}
		// If only one scan matches and it's the current report, we can't compare
		if previousReport == currentReport {
			return fmt.Errorf("only one scan found since %s; at least 2 scans are required for comparison", sinceDate)
		}
	} else {
		// Default: compare with the previous scan
		previousReport = reports[1]
	}

	// Generate comparison result
	comparison := compareReports(previousReport, currentReport)

	// Output the result
	if jsonOutput {
		return outputComparisonJSON(comparison)
	}
	if markdownOutput {
		return outputComparisonMarkdown(comparison)
	}
	return outputComparisonText(comparison)
}

// ComparisonResult holds the result of comparing two scan reports.
type ComparisonResult struct {
	// OnionService is the scanned hidden service address.
	OnionService string `json:"onion_service"`

	// PreviousScan contains metadata about the previous scan.
	PreviousScan ScanMetadata `json:"previous_scan"`

	// CurrentScan contains metadata about the current scan.
	CurrentScan ScanMetadata `json:"current_scan"`

	// NewFindings contains findings that are new in the current scan.
	NewFindings []model.Finding `json:"new_findings,omitempty"`

	// ResolvedFindings contains findings that were in the previous scan but not in current.
	ResolvedFindings []model.Finding `json:"resolved_findings,omitempty"`

	// UnchangedCount is the number of findings that remain unchanged.
	UnchangedCount int `json:"unchanged_count"`

	// RiskChange describes the overall change in risk level.
	RiskChange RiskChange `json:"risk_change"`
}

// ScanMetadata contains metadata about a scan for comparison display.
type ScanMetadata struct {
	// DateScanned is when the scan was performed.
	DateScanned time.Time `json:"date_scanned"`

	// TotalFindings is the total number of findings in this scan.
	TotalFindings int `json:"total_findings"`

	// CriticalCount is the number of critical findings.
	CriticalCount int `json:"critical_count"`

	// HighCount is the number of high severity findings.
	HighCount int `json:"high_count"`

	// MediumCount is the number of medium severity findings.
	MediumCount int `json:"medium_count"`

	// LowCount is the number of low severity findings.
	LowCount int `json:"low_count"`

	// InfoCount is the number of informational findings.
	InfoCount int `json:"info_count"`
}

// RiskChange describes the change in risk level between scans.
type RiskChange struct {
	// Direction is "improved", "worsened", or "unchanged".
	Direction string `json:"direction"`

	// CriticalDelta is the change in critical findings count.
	CriticalDelta int `json:"critical_delta"`

	// HighDelta is the change in high severity findings count.
	HighDelta int `json:"high_delta"`

	// MediumDelta is the change in medium severity findings count.
	MediumDelta int `json:"medium_delta"`

	// LowDelta is the change in low severity findings count.
	LowDelta int `json:"low_delta"`

	// InfoDelta is the change in informational findings count.
	InfoDelta int `json:"info_delta"`
}

// compareReports compares two scan reports and generates a comparison result.
func compareReports(previous, current *model.OnionScanReport) *ComparisonResult {
	result := &ComparisonResult{
		OnionService: current.HiddenService,
	}

	// Extract metadata
	if previous.SimpleReport != nil {
		result.PreviousScan = ScanMetadata{
			DateScanned:   previous.DateScanned,
			TotalFindings: len(previous.SimpleReport.Findings),
			CriticalCount: previous.SimpleReport.CriticalCount,
			HighCount:     previous.SimpleReport.HighCount,
			MediumCount:   previous.SimpleReport.MediumCount,
			LowCount:      previous.SimpleReport.LowCount,
			InfoCount:     previous.SimpleReport.InfoCount,
		}
	} else {
		result.PreviousScan = ScanMetadata{DateScanned: previous.DateScanned}
	}

	if current.SimpleReport != nil {
		result.CurrentScan = ScanMetadata{
			DateScanned:   current.DateScanned,
			TotalFindings: len(current.SimpleReport.Findings),
			CriticalCount: current.SimpleReport.CriticalCount,
			HighCount:     current.SimpleReport.HighCount,
			MediumCount:   current.SimpleReport.MediumCount,
			LowCount:      current.SimpleReport.LowCount,
			InfoCount:     current.SimpleReport.InfoCount,
		}
	} else {
		result.CurrentScan = ScanMetadata{DateScanned: current.DateScanned}
	}

	// Build finding maps for comparison
	previousFindings := make(map[string]model.Finding)
	currentFindings := make(map[string]model.Finding)

	if previous.SimpleReport != nil {
		for _, f := range previous.SimpleReport.Findings {
			key := findingKey(f)
			previousFindings[key] = f
		}
	}

	if current.SimpleReport != nil {
		for _, f := range current.SimpleReport.Findings {
			key := findingKey(f)
			currentFindings[key] = f
		}
	}

	// Find new findings (in current but not in previous)
	for key, finding := range currentFindings {
		if _, exists := previousFindings[key]; !exists {
			result.NewFindings = append(result.NewFindings, finding)
		}
	}

	// Find resolved findings (in previous but not in current)
	for key, finding := range previousFindings {
		if _, exists := currentFindings[key]; !exists {
			result.ResolvedFindings = append(result.ResolvedFindings, finding)
		} else {
			result.UnchangedCount++
		}
	}

	// Calculate risk change
	result.RiskChange = calculateRiskChange(result.PreviousScan, result.CurrentScan)

	return result
}

// findingKey generates a unique key for a finding for comparison purposes.
func findingKey(f model.Finding) string {
	return f.Type + "|" + f.Value + "|" + f.Location
}

// calculateRiskChange calculates the change in risk between two scans.
func calculateRiskChange(previous, current ScanMetadata) RiskChange {
	change := RiskChange{
		CriticalDelta: current.CriticalCount - previous.CriticalCount,
		HighDelta:     current.HighCount - previous.HighCount,
		MediumDelta:   current.MediumCount - previous.MediumCount,
		LowDelta:      current.LowCount - previous.LowCount,
		InfoDelta:     current.InfoCount - previous.InfoCount,
	}

	// Determine overall direction based on weighted score
	// Critical and High severity changes have more weight
	previousScore := previous.CriticalCount*100 + previous.HighCount*50 + previous.MediumCount*10 + previous.LowCount*5 + previous.InfoCount
	currentScore := current.CriticalCount*100 + current.HighCount*50 + current.MediumCount*10 + current.LowCount*5 + current.InfoCount

	if currentScore < previousScore {
		change.Direction = riskDirectionImproved
	} else if currentScore > previousScore {
		change.Direction = riskDirectionWorsened
	} else {
		change.Direction = riskDirectionUnchanged
	}

	return change
}

// outputComparisonJSON outputs the comparison result in JSON format.
func outputComparisonJSON(result *ComparisonResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// outputComparisonMarkdown outputs the comparison result in Markdown format.
func outputComparisonMarkdown(result *ComparisonResult) error {
	fmt.Printf("# Scan Comparison: %s\n\n", result.OnionService)

	// Risk change summary
	fmt.Println("## Summary")
	fmt.Printf("\n**Risk Status:** %s\n\n", formatRiskDirection(result.RiskChange.Direction))

	// Scan metadata table
	fmt.Println("| Metric | Previous | Current | Change |")
	fmt.Println("|--------|----------|---------|--------|")
	fmt.Printf("| Date | %s | %s | - |\n",
		result.PreviousScan.DateScanned.Format("2006-01-02 15:04"),
		result.CurrentScan.DateScanned.Format("2006-01-02 15:04"))
	fmt.Printf("| Critical | %d | %d | %s |\n",
		result.PreviousScan.CriticalCount,
		result.CurrentScan.CriticalCount,
		formatDelta(result.RiskChange.CriticalDelta))
	fmt.Printf("| High | %d | %d | %s |\n",
		result.PreviousScan.HighCount,
		result.CurrentScan.HighCount,
		formatDelta(result.RiskChange.HighDelta))
	fmt.Printf("| Medium | %d | %d | %s |\n",
		result.PreviousScan.MediumCount,
		result.CurrentScan.MediumCount,
		formatDelta(result.RiskChange.MediumDelta))
	fmt.Printf("| Low | %d | %d | %s |\n",
		result.PreviousScan.LowCount,
		result.CurrentScan.LowCount,
		formatDelta(result.RiskChange.LowDelta))
	fmt.Printf("| Info | %d | %d | %s |\n",
		result.PreviousScan.InfoCount,
		result.CurrentScan.InfoCount,
		formatDelta(result.RiskChange.InfoDelta))
	fmt.Printf("| **Total** | **%d** | **%d** | **%s** |\n",
		result.PreviousScan.TotalFindings,
		result.CurrentScan.TotalFindings,
		formatDelta(result.CurrentScan.TotalFindings-result.PreviousScan.TotalFindings))

	// New findings
	if len(result.NewFindings) > 0 {
		fmt.Printf("\n## New Findings (%d)\n\n", len(result.NewFindings))
		for _, f := range result.NewFindings {
			fmt.Printf("- **[%s]** %s: %s\n", f.SeverityText, f.Title, f.Value)
			if f.Location != "" {
				fmt.Printf("  - Location: `%s`\n", f.Location)
			}
		}
	}

	// Resolved findings
	if len(result.ResolvedFindings) > 0 {
		fmt.Printf("\n## Resolved Findings (%d)\n\n", len(result.ResolvedFindings))
		for _, f := range result.ResolvedFindings {
			fmt.Printf("- ~~**[%s]** %s: %s~~\n", f.SeverityText, f.Title, f.Value)
		}
	}

	// Unchanged count
	if result.UnchangedCount > 0 {
		fmt.Printf("\n---\n\n*%d findings unchanged*\n", result.UnchangedCount)
	}

	return nil
}

// outputComparisonText outputs the comparison result in human-readable text format.
func outputComparisonText(result *ComparisonResult) error {
	fmt.Printf("Scan Comparison: %s\n", result.OnionService)
	fmt.Println(strings.Repeat("=", 60))

	// Risk change summary
	fmt.Printf("\nRisk Status: %s\n", formatRiskDirection(result.RiskChange.Direction))

	// Scan dates
	fmt.Printf("\nPrevious scan: %s\n", result.PreviousScan.DateScanned.Format("2006-01-02 15:04:05"))
	fmt.Printf("Current scan:  %s\n", result.CurrentScan.DateScanned.Format("2006-01-02 15:04:05"))

	// Summary table
	fmt.Println("\nFindings Summary:")
	fmt.Printf("  %-10s  %-10s  %-10s  %-10s\n", "Severity", "Previous", "Current", "Change")
	fmt.Println("  " + strings.Repeat("-", 45))
	fmt.Printf("  %-10s  %-10d  %-10d  %-10s\n", "Critical",
		result.PreviousScan.CriticalCount, result.CurrentScan.CriticalCount,
		formatDelta(result.RiskChange.CriticalDelta))
	fmt.Printf("  %-10s  %-10d  %-10d  %-10s\n", "High",
		result.PreviousScan.HighCount, result.CurrentScan.HighCount,
		formatDelta(result.RiskChange.HighDelta))
	fmt.Printf("  %-10s  %-10d  %-10d  %-10s\n", "Medium",
		result.PreviousScan.MediumCount, result.CurrentScan.MediumCount,
		formatDelta(result.RiskChange.MediumDelta))
	fmt.Printf("  %-10s  %-10d  %-10d  %-10s\n", "Low",
		result.PreviousScan.LowCount, result.CurrentScan.LowCount,
		formatDelta(result.RiskChange.LowDelta))
	fmt.Printf("  %-10s  %-10d  %-10d  %-10s\n", "Info",
		result.PreviousScan.InfoCount, result.CurrentScan.InfoCount,
		formatDelta(result.RiskChange.InfoDelta))
	fmt.Println("  " + strings.Repeat("-", 45))
	fmt.Printf("  %-10s  %-10d  %-10d  %-10s\n", "Total",
		result.PreviousScan.TotalFindings, result.CurrentScan.TotalFindings,
		formatDelta(result.CurrentScan.TotalFindings-result.PreviousScan.TotalFindings))

	// New findings
	if len(result.NewFindings) > 0 {
		fmt.Printf("\nNew Findings (%d):\n", len(result.NewFindings))
		for _, f := range result.NewFindings {
			fmt.Printf("  [+] [%s] %s: %s\n", f.SeverityText, f.Title, f.Value)
			if f.Location != "" {
				fmt.Printf("      Location: %s\n", f.Location)
			}
		}
	}

	// Resolved findings
	if len(result.ResolvedFindings) > 0 {
		fmt.Printf("\nResolved Findings (%d):\n", len(result.ResolvedFindings))
		for _, f := range result.ResolvedFindings {
			fmt.Printf("  [-] [%s] %s: %s\n", f.SeverityText, f.Title, f.Value)
		}
	}

	// Unchanged count
	if result.UnchangedCount > 0 {
		fmt.Printf("\nUnchanged: %d findings\n", result.UnchangedCount)
	}

	return nil
}

// formatRiskDirection formats the risk change direction for display.
func formatRiskDirection(direction string) string {
	switch direction {
	case riskDirectionImproved:
		return "IMPROVED (risk decreased)"
	case riskDirectionWorsened:
		return "WORSENED (risk increased)"
	default:
		return "UNCHANGED"
	}
}

// formatDelta formats a numeric delta with sign for display.
func formatDelta(delta int) string {
	if delta > 0 {
		return "+" + strconv.Itoa(delta)
	} else if delta < 0 {
		return strconv.Itoa(delta)
	}
	return "0"
}
