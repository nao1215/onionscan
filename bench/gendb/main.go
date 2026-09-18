// Command gendb writes the scan history the himorime suite in bench/ reads:
// an onionscan.db holding two scans of one onion service, each with N
// findings. Nine in ten findings are in both scans, one in ten only in the
// earlier scan (resolved) and one in ten only in the later one (new), so
// `onionscan compare` reports all three kinds. The output is the same for the
// same arguments. It is run through bench/gen.sh.
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nao1215/onionscan/internal/database"
	"github.com/nao1215/onionscan/internal/model"
	"github.com/nao1215/onionscan/internal/tor"
)

// address is a valid v3 onion address derived from a fixed key. It is only
// written into the local database; nothing connects to it.
const address = "n5xgs33oonrwc3ranbuw233snfwwkidcmvxgg2dnmfzgwidlmv4twaad.onion"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gendb:", err)
		os.Exit(1)
	}
}

func run() error {
	findings := flag.Int("findings", 10, "findings in each scan")
	dir := flag.String("dir", "", "directory to write onionscan.db into")
	flag.Parse()
	if *dir == "" || *findings < 1 {
		return errors.New("usage: gendb -findings N -dir DIR")
	}
	if _, err := tor.NormalizeAddress(address); err != nil {
		return fmt.Errorf("fixed address %s: %w", address, err)
	}
	if err := os.RemoveAll(*dir); err != nil {
		return err
	}

	ctx := context.Background()
	db, err := database.Open(*dir, database.DefaultOptions())
	if err != nil {
		return err
	}
	shift := max(*findings/10, 1)
	earlier := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	later := earlier.Add(24 * time.Hour)
	for _, r := range []*model.OnionScanReport{
		report(earlier, 0, *findings),
		report(later, shift, *findings),
	} {
		if err := db.SaveScanReport(ctx, r); err != nil {
			_ = db.Close()
			return err
		}
	}
	if err := db.Close(); err != nil {
		return err
	}
	return setTimestamps(ctx, filepath.Join(*dir, "onionscan.db"), earlier, later)
}

// setTimestamps gives the two rows the dates of their reports. The table
// stamps a row with the second it was written, so both rows would otherwise
// share one and the order of the history would be undefined.
func setTimestamps(ctx context.Context, path string, earlier, later time.Time) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	const layout = "2006-01-02 15:04:05"
	for id, at := range map[int]time.Time{1: earlier, 2: later} {
		if _, err := db.ExecContext(ctx, "UPDATE scan_reports SET timestamp = ? WHERE id = ?", at.Format(layout), id); err != nil {
			return err
		}
	}
	return nil
}

// report returns a scan dated at holding the findings first to first+n-1.
func report(at time.Time, first, n int) *model.OnionScanReport {
	severities := []model.Severity{model.SeverityInfo, model.SeverityLow, model.SeverityMedium, model.SeverityHigh, model.SeverityCritical}
	simple := &model.SimpleReport{HiddenService: address, DateScanned: at, PagesCrawled: n}
	simple.Findings = make([]model.Finding, 0, n)
	for i := first; i < first+n; i++ {
		s := severities[i%len(severities)]
		switch s {
		case model.SeverityInfo:
			simple.InfoCount++
		case model.SeverityLow:
			simple.LowCount++
		case model.SeverityMedium:
			simple.MediumCount++
		case model.SeverityHigh:
			simple.HighCount++
		case model.SeverityCritical:
			simple.CriticalCount++
		}
		simple.Findings = append(simple.Findings, model.Finding{
			Type:           fmt.Sprintf("email_address_%d", i%7),
			Severity:       s,
			SeverityText:   s.String(),
			Title:          "Email address exposed",
			Description:    "An email address was found in the page content.",
			Impact:         "An email address can link the service to its operator.",
			Recommendation: "Remove the address or use one that is not tied to an identity.",
			Value:          fmt.Sprintf("user%d@example.com", i),
			Location:       fmt.Sprintf("http://%s/page/%d", address, i),
		})
	}
	return &model.OnionScanReport{
		HiddenService: address,
		OnionVersion:  3,
		DateScanned:   at,
		WebDetected:   true,
		SimpleReport:  simple,
	}
}
