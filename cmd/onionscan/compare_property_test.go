package main

import (
	"slices"
	"testing"
	"time"

	"github.com/nao1215/onionscan/internal/model"
	"pgregory.net/rapid"
)

// findingID is the identity compare uses to match a finding across two scans:
// the same type, value and location.
type findingID struct {
	typ, value, location string
}

func idOf(f model.Finding) findingID {
	return findingID{typ: f.Type, value: f.Value, location: f.Location}
}

// findingGen draws findings from a small space so that two scans share some
// findings and differ in others. Values and locations may contain "|", the
// character that separates the parts of the key compare builds.
func findingGen() *rapid.Generator[model.Finding] {
	return rapid.Custom(func(t *rapid.T) model.Finding {
		typ := rapid.SampledFrom([]string{
			"email_address", "bitcoin_address", "server_banner", "clearnet_link", "apache_mod_status",
		}).Draw(t, "type")
		info := model.GetFindingInfo(typ)
		return model.Finding{
			Type:         typ,
			Severity:     info.Severity,
			SeverityText: info.Severity.String(),
			Title:        typ,
			Value:        rapid.StringOfN(rapid.RuneFrom([]rune("ab|")), 0, 3, -1).Draw(t, "value"),
			Location:     rapid.StringOfN(rapid.RuneFrom([]rune("/x|")), 0, 3, -1).Draw(t, "location"),
		}
	})
}

// reportGen draws a stored scan report with distinct findings, the way the
// analyzers produce them, and severity counts that match the findings.
func reportGen(label string) *rapid.Generator[*model.OnionScanReport] {
	return rapid.Custom(func(t *rapid.T) *model.OnionScanReport {
		findings := rapid.SliceOfDistinct(findingGen(), idOf).Draw(t, label)
		simple := &model.SimpleReport{Findings: findings}
		for _, f := range findings {
			switch f.Severity {
			case model.SeverityCritical:
				simple.CriticalCount++
			case model.SeverityHigh:
				simple.HighCount++
			case model.SeverityMedium:
				simple.MediumCount++
			case model.SeverityLow:
				simple.LowCount++
			case model.SeverityInfo:
				simple.InfoCount++
			}
		}
		r := model.NewOnionScanReport("example.onion")
		r.DateScanned = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		r.SimpleReport = simple
		return r
	})
}

func idSet(findings []model.Finding) map[findingID]bool {
	set := make(map[findingID]bool, len(findings))
	for _, f := range findings {
		set[idOf(f)] = true
	}
	return set
}

// TestPropertyCompareReportsPartitionsFindingsByIdentity checks the result against
// the definition: new findings are in the current scan only, resolved ones in
// the previous scan only, and the rest are counted as unchanged.
func TestPropertyCompareReportsPartitionsFindingsByIdentity(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		previous := reportGen("previous").Draw(t, "previous")
		current := reportGen("current").Draw(t, "current")

		result := compareReports(previous, current)

		before := idSet(previous.SimpleReport.Findings)
		after := idSet(current.SimpleReport.Findings)
		var wantNew, wantResolved []findingID
		wantUnchanged := 0
		for _, f := range current.SimpleReport.Findings {
			if !before[idOf(f)] {
				wantNew = append(wantNew, idOf(f))
			}
		}
		for _, f := range previous.SimpleReport.Findings {
			if after[idOf(f)] {
				wantUnchanged++
			} else {
				wantResolved = append(wantResolved, idOf(f))
			}
		}

		gotNew := make([]findingID, 0, len(result.NewFindings))
		for _, f := range result.NewFindings {
			gotNew = append(gotNew, idOf(f))
		}
		gotResolved := make([]findingID, 0, len(result.ResolvedFindings))
		for _, f := range result.ResolvedFindings {
			gotResolved = append(gotResolved, idOf(f))
		}
		if !sameIDs(gotNew, wantNew) {
			t.Fatalf("new findings: got %v, want %v", gotNew, wantNew)
		}
		if !sameIDs(gotResolved, wantResolved) {
			t.Fatalf("resolved findings: got %v, want %v", gotResolved, wantResolved)
		}
		if result.UnchangedCount != wantUnchanged {
			t.Fatalf("unchanged: got %d, want %d", result.UnchangedCount, wantUnchanged)
		}
	})
}

// TestPropertyCompareReportsSwappingTheScansSwapsNewAndResolved is a metamorphic
// relation: comparing the scans the other way round turns every new finding
// into a resolved one and back, keeps the unchanged count and reverses the
// risk direction.
func TestPropertyCompareReportsSwappingTheScansSwapsNewAndResolved(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		a := reportGen("a").Draw(t, "a")
		b := reportGen("b").Draw(t, "b")

		forward := compareReports(a, b)
		backward := compareReports(b, a)

		if !sameFindings(forward.NewFindings, backward.ResolvedFindings) {
			t.Fatalf("new a->b %v != resolved b->a %v", forward.NewFindings, backward.ResolvedFindings)
		}
		if !sameFindings(forward.ResolvedFindings, backward.NewFindings) {
			t.Fatalf("resolved a->b %v != new b->a %v", forward.ResolvedFindings, backward.NewFindings)
		}
		if forward.UnchangedCount != backward.UnchangedCount {
			t.Fatalf("unchanged a->b %d != b->a %d", forward.UnchangedCount, backward.UnchangedCount)
		}
		reversed := map[string]string{
			riskDirectionImproved:  riskDirectionWorsened,
			riskDirectionWorsened:  riskDirectionImproved,
			riskDirectionUnchanged: riskDirectionUnchanged,
		}
		if backward.RiskChange.Direction != reversed[forward.RiskChange.Direction] {
			t.Fatalf("direction a->b %q, b->a %q", forward.RiskChange.Direction, backward.RiskChange.Direction)
		}
	})
}

// TestPropertyCompareReportsWithItselfFindsNoChange checks that a scan compared with
// itself has nothing new or resolved, everything unchanged and an unchanged
// risk.
func TestPropertyCompareReportsWithItselfFindsNoChange(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		r := reportGen("report").Draw(t, "report")

		result := compareReports(r, r)

		if len(result.NewFindings) != 0 || len(result.ResolvedFindings) != 0 {
			t.Fatalf("got new %v and resolved %v", result.NewFindings, result.ResolvedFindings)
		}
		if result.UnchangedCount != len(r.SimpleReport.Findings) {
			t.Fatalf("unchanged: got %d, want %d", result.UnchangedCount, len(r.SimpleReport.Findings))
		}
		if result.RiskChange.Direction != riskDirectionUnchanged {
			t.Fatalf("direction: got %q", result.RiskChange.Direction)
		}
	})
}

// TestPropertyCompareReportsListsFindingsInReportOrder checks that the comparison is
// deterministic: new findings appear in the order the current scan reported
// them and resolved findings in the order the previous scan did, so running
// compare twice on the same history prints the same report.
func TestPropertyCompareReportsListsFindingsInReportOrder(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		previous := reportGen("previous").Draw(t, "previous")
		current := reportGen("current").Draw(t, "current")

		result := compareReports(previous, current)

		after := idSet(current.SimpleReport.Findings)
		before := idSet(previous.SimpleReport.Findings)
		var wantNew, wantResolved []model.Finding
		for _, f := range current.SimpleReport.Findings {
			if !before[idOf(f)] {
				wantNew = append(wantNew, f)
			}
		}
		for _, f := range previous.SimpleReport.Findings {
			if !after[idOf(f)] {
				wantResolved = append(wantResolved, f)
			}
		}
		if !slices.Equal(result.NewFindings, wantNew) {
			t.Fatalf("new findings: got %v, want %v", result.NewFindings, wantNew)
		}
		if !slices.Equal(result.ResolvedFindings, wantResolved) {
			t.Fatalf("resolved findings: got %v, want %v", result.ResolvedFindings, wantResolved)
		}
	})
}

func sameIDs(a, b []findingID) bool {
	count := make(map[findingID]int)
	for _, id := range a {
		count[id]++
	}
	for _, id := range b {
		count[id]--
	}
	for _, n := range count {
		if n != 0 {
			return false
		}
	}
	return true
}

func sameFindings(a, b []model.Finding) bool {
	ids := func(fs []model.Finding) []findingID {
		out := make([]findingID, 0, len(fs))
		for _, f := range fs {
			out = append(out, idOf(f))
		}
		return out
	}
	return sameIDs(ids(a), ids(b))
}
