package detect

import (
	"net/netip"
	"testing"
	"time"

	"github.com/kilo666mj/dnsgate/internal/store"
)

func defaults() Thresholds {
	return Thresholds{
		QueriesPerMinute:     60,
		SingleLabelPerMinute: 10,
		NXDomainRatio:        0.5,
		MinQueries:           200,
	}
}

func row(client, domain string, c store.Counters, spanMinutes int) store.Row {
	start := time.Date(2026, 8, 4, 20, 38, 0, 0, time.UTC)
	c.FirstSeen = start
	c.LastSeen = start.Add(time.Duration(spanMinutes) * time.Minute)
	return store.Row{
		Key:      store.Key{Client: netip.MustParseAddr(client), Domain: domain, Day: "2026-08-04"},
		Counters: c,
	}
}

// The case this was written for. On 2026-08-04 the host at 192.168.253.123
// queried bare "swarm" (NXDOMAIN) and then "swarm.internal" 88 times a minute
// each, which was 46% of all DNS on the network and 84% of all NXDOMAIN. It
// was found by hand. These detectors exist so the next one is not.
func TestFindsTheSwarmLoop(t *testing.T) {
	rows := []store.Row{
		row("192.168.253.123", "swarm", store.Counters{Queries: 2978, NXDomain: 2978, SingleLabel: 2978}, 34),
		row("192.168.253.123", "swarm.internal", store.Counters{Queries: 2978, Cached: 2900}, 34),
		row("192.168.253.123", "github.com", store.Counters{Queries: 264}, 34),
		// A normal client, for contrast: it must not be flagged.
		row("192.168.253.120", "github.com", store.Counters{Queries: 240}, 34),
	}

	findings := Run(rows, defaults())
	if len(findings) == 0 {
		t.Fatal("no findings; the loop must be detected")
	}

	byKind := map[Kind]Finding{}
	for _, f := range findings {
		if f.Client.String() == "192.168.253.120" {
			t.Errorf("flagged the quiet client: %+v", f)
		}
		byKind[f.Kind] = f
	}

	rate, ok := byKind[KindQueryRate]
	if !ok {
		t.Fatal("no query-rate finding")
	}
	// 6220 queries over 34 minutes is ~183/min.
	if rate.Value < 150 || rate.Value > 220 {
		t.Errorf("rate = %.0f/min, want ~183", rate.Value)
	}
	if rate.TopDomains[0] != "swarm" && rate.TopDomains[0] != "swarm.internal" {
		t.Errorf("top domains = %v, want the loop named first", rate.TopDomains)
	}

	loop, ok := byKind[KindSingleLabelLoop]
	if !ok {
		t.Fatal("no single-label finding; this is the one that names the cause")
	}
	if loop.Queries != 2978 {
		t.Errorf("single-label queries = %d, want 2978", loop.Queries)
	}

	// Worth stating plainly, because it justifies having three detectors
	// rather than one: this client's own NXDOMAIN rate was 2978/6220 = 47.9%,
	// which is *below* the 50% default and does not fire. A search-domain
	// loop pairs each failure with a success, so it structurally cannot push
	// the ratio much past half. The single-label detector is what catches
	// this shape; tuning the NXDOMAIN threshold down to 0.45 to "fix" that
	// would trade a precise signal for a noisy one.
	if f, ok := byKind[KindNXDomainRate]; ok {
		t.Errorf("nxdomain fired at %.3f against a %.2f threshold; a search-domain "+
			"loop should be caught by the single-label detector instead", f.Value, f.Threshold)
	}
}

// A domain-generation algorithm is the shape the NXDOMAIN detector is for:
// failures without matching successes, so the ratio goes far past half.
func TestFindsMostlyFailingClient(t *testing.T) {
	rows := []store.Row{
		row("192.168.253.90", "a1b2c3.example.com", store.Counters{Queries: 900, NXDomain: 880}, 34),
		row("192.168.253.90", "github.com", store.Counters{Queries: 100}, 34),
	}
	var found bool
	for _, f := range Run(rows, defaults()) {
		if f.Kind == KindNXDomainRate {
			found = true
			if f.Value < 0.85 {
				t.Errorf("ratio = %.2f, want ~0.88", f.Value)
			}
		}
	}
	if !found {
		t.Error("no nxdomain finding; 880 of 1000 lookups failed")
	}
}

// A client below MinQueries must not be judged, or a host that asks twice and
// misses once reads as a 50% failure rate.
func TestIgnoresLowVolume(t *testing.T) {
	rows := []store.Row{
		row("192.168.253.50", "broken.example.com", store.Counters{Queries: 2, NXDomain: 2, SingleLabel: 2}, 1),
	}
	if got := Run(rows, defaults()); len(got) != 0 {
		t.Errorf("findings = %+v, want none below the volume floor", got)
	}
}

// Rates come from the span a client was actually observed over, not the length
// of the day — otherwise a short intense burst averages away to nothing.
func TestRateUsesObservedSpan(t *testing.T) {
	// 600 queries in 5 minutes is 120/min and must fire; the same 600 spread
	// over 12 hours is 0.8/min and must not.
	burst := []store.Row{row("192.168.253.51", "example.com", store.Counters{Queries: 600}, 5)}
	spread := []store.Row{row("192.168.253.52", "example.com", store.Counters{Queries: 600}, 720)}

	if got := Run(burst, defaults()); len(got) == 0 {
		t.Error("a 120/min burst was not flagged")
	}
	if got := Run(spread, defaults()); len(got) != 0 {
		t.Errorf("steady traffic flagged: %+v", got)
	}
}

// A span under a minute would make any rate arbitrarily large.
func TestVeryShortSpanDoesNotExplode(t *testing.T) {
	rows := []store.Row{row("192.168.253.53", "example.com", store.Counters{Queries: 250}, 0)}
	findings := Run(rows, defaults())
	for _, f := range findings {
		if f.Value > 1000 {
			t.Errorf("rate = %.0f, implausible for a sub-minute span", f.Value)
		}
	}
}

// Findings must be ordered worst-first and stably, or alert deduplication
// downstream is impossible.
func TestFindingsAreOrderedAndStable(t *testing.T) {
	rows := []store.Row{
		row("192.168.253.60", "a.example.com", store.Counters{Queries: 3400}, 34), // ~100/min
		row("192.168.253.61", "b.example.com", store.Counters{Queries: 8500}, 34), // ~250/min
	}
	first := Run(rows, defaults())
	if len(first) < 2 {
		t.Fatalf("findings = %d, want both clients flagged", len(first))
	}
	if first[0].Client.String() != "192.168.253.61" {
		t.Errorf("leading finding = %s, want the worst offender", first[0].Client)
	}
	for i := range 5 {
		again := Run(rows, defaults())
		for j := range first {
			if again[j].Client != first[j].Client || again[j].Kind != first[j].Kind {
				t.Fatalf("run %d differed at %d: %v vs %v", i, j, again[j], first[j])
			}
		}
	}
}

func TestDisabledThresholdsDoNotFire(t *testing.T) {
	rows := []store.Row{
		row("192.168.253.70", "swarm", store.Counters{Queries: 5000, NXDomain: 5000, SingleLabel: 5000}, 10),
	}
	if got := Run(rows, Thresholds{MinQueries: 1}); len(got) != 0 {
		t.Errorf("findings = %+v, want none when every threshold is zero", got)
	}
}

func TestSeparatesClientsAndDays(t *testing.T) {
	a := row("192.168.253.80", "example.com", store.Counters{Queries: 3400}, 34)
	b := row("192.168.253.80", "example.com", store.Counters{Queries: 3400}, 34)
	b.Day = "2026-08-05"

	findings := Run([]store.Row{a, b}, defaults())
	days := map[string]bool{}
	for _, f := range findings {
		if f.Kind == KindQueryRate {
			days[f.Day] = true
		}
	}
	if len(days) != 2 {
		t.Errorf("days flagged = %v, want each day judged separately", days)
	}
}

func TestNoRowsIsNoFindings(t *testing.T) {
	if got := Run(nil, defaults()); len(got) != 0 {
		t.Errorf("findings = %+v, want none", got)
	}
}
