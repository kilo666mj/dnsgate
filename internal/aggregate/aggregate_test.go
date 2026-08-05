package aggregate

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/kilo666mj/dnsgate/internal/dnsquery"
	"github.com/kilo666mj/dnsgate/internal/store"
)

// The names here are the ones actually seen on this network in the first
// half-hour of looking, not invented examples: the search-domain artifact that
// turned out to be 46% of all traffic, the internal name behind it, the
// reverse lookups, and a CDN-fronted telemetry endpoint.
func TestClassify(t *testing.T) {
	for name, want := range map[string]Classification{
		"swarm":                              SingleLabel,
		"swarm.internal":                     Registrable,
		"http-intake.logs.us5.datadoghq.com": Registrable,
		"253.168.192.in-addr.arpa":           Reverse,
		"1.0.0.0.ip6.arpa":                   Reverse,
		"":                                   SingleLabel,
		"SWARM.":                             SingleLabel,
	} {
		if got := Classify(name); got != want {
			t.Errorf("Classify(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestDomain(t *testing.T) {
	for name, want := range map[string]string{
		// The collapse that makes the baseline finite.
		"http-intake.logs.us5.datadoghq.com": "datadoghq.com",
		"a3f9c1.telemetry.vendor.com":        "vendor.com",
		"b7e204.telemetry.vendor.com":        "vendor.com",
		"api.github.com":                     "github.com",
		// A multi-part public suffix must not collapse to the suffix itself.
		"foo.bar.co.uk": "bar.co.uk",
		// An unlisted TLD is treated as the suffix, so ".internal" names keep
		// their own identity rather than all collapsing together.
		"swarm.internal":      "swarm.internal",
		"puppet.internal":     "puppet.internal",
		"mx.michaelspost.com": "michaelspost.com",
		// No registrable form: returned as-is, and Classify keeps them out of
		// the baseline.
		"swarm":                    "swarm",
		"253.168.192.in-addr.arpa": "253.168.192.in-addr.arpa",
		// Normalization.
		"API.GitHub.Com.": "github.com",
	} {
		if got := Domain(name); got != want {
			t.Errorf("Domain(%q) = %q, want %q", name, got, want)
		}
	}
}

// Two names under one registrable domain must land in one bucket — that is
// the entire point of the collapse.
func TestAddCollapsesToRegistrableDomain(t *testing.T) {
	a := New()
	when := time.Date(2026, 8, 4, 21, 47, 15, 0, time.UTC)
	for _, n := range []string{"a3f9c1.telemetry.vendor.com", "b7e204.telemetry.vendor.com"} {
		a.Add(dnsquery.Query{
			Time: when, Client: netip.MustParseAddr("192.168.253.123"),
			QName: n, RCode: "NoError", Protocol: "Udp",
		})
	}
	if got := a.Pending(); got != 1 {
		t.Fatalf("pending buckets = %d, want 1", got)
	}
	sink := &fakeSink{}
	if _, err := a.Flush(t.Context(), sink); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	k := store.Key{Client: netip.MustParseAddr("192.168.253.123"), Domain: "vendor.com", Day: "2026-08-04"}
	if got := sink.last[k].Queries; got != 2 {
		t.Errorf("queries = %d, want 2 folded into one bucket", got)
	}
}

func TestAddCountsFlags(t *testing.T) {
	a := New()
	when := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	client := netip.MustParseAddr("192.168.253.123")

	// The real pattern: a bare single-label NXDOMAIN followed by the
	// search-domain-expanded name that succeeds.
	a.Add(dnsquery.Query{Time: when, Client: client, QName: "swarm", RCode: "NxDomain", Protocol: "Udp"})
	a.Add(dnsquery.Query{Time: when, Client: client, QName: "swarm.internal", RCode: "NoError", Protocol: "Udp", Cached: true})
	a.Add(dnsquery.Query{Time: when, Client: client, QName: "253.168.192.in-addr.arpa", RCode: "NoError", Protocol: "Udp"})
	a.Add(dnsquery.Query{Time: when, Client: client, QName: "api.github.com", RCode: "NoError", Protocol: "Https"})

	sink := &fakeSink{}
	n, err := a.Flush(t.Context(), sink)
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if n != 4 {
		t.Fatalf("flushed %d buckets, want 4", n)
	}

	get := func(domain string) store.Counters {
		return sink.last[store.Key{Client: client, Domain: domain, Day: "2026-08-04"}]
	}
	if c := get("swarm"); c.SingleLabel != 1 || c.NXDomain != 1 {
		t.Errorf("swarm: %+v, want single-label NXDOMAIN", c)
	}
	if c := get("swarm.internal"); c.SingleLabel != 0 || c.Cached != 1 {
		t.Errorf("swarm.internal: %+v, want a cached registrable name", c)
	}
	if c := get("253.168.192.in-addr.arpa"); c.Reverse != 1 {
		t.Errorf("reverse lookup: %+v", c)
	}
	if c := get("github.com"); c.Encrypted != 1 {
		t.Errorf("github.com over Https: %+v, want encrypted counted", c)
	}
}

// A query with no client cannot be attributed, and a bucket without one would
// silently merge unrelated hosts — the mistake egressgate made by allowing
// "unknown" into a key.
func TestAddDropsUnusableQueries(t *testing.T) {
	a := New()
	a.Add(dnsquery.Query{QName: "example.com", Time: time.Now()})
	a.Add(dnsquery.Query{Client: netip.MustParseAddr("192.168.253.1"), Time: time.Now()})
	if got := a.Pending(); got != 0 {
		t.Errorf("pending = %d, want 0", got)
	}
}

func TestAddSpansDays(t *testing.T) {
	a := New()
	client := netip.MustParseAddr("192.168.253.1")
	a.Add(dnsquery.Query{Time: time.Date(2026, 8, 4, 23, 59, 0, 0, time.UTC), Client: client, QName: "api.github.com"})
	a.Add(dnsquery.Query{Time: time.Date(2026, 8, 5, 0, 1, 0, 0, time.UTC), Client: client, QName: "api.github.com"})
	if got := a.Pending(); got != 2 {
		t.Errorf("pending = %d, want one bucket per day", got)
	}
}

// A failed write must not cost the observations. Losing an hour of counters
// to a transient database error would be invisible and unrecoverable.
func TestFlushRestoresBatchOnError(t *testing.T) {
	a := New()
	client := netip.MustParseAddr("192.168.253.1")
	a.Add(dnsquery.Query{Time: time.Now(), Client: client, QName: "api.github.com"})

	failing := &fakeSink{err: errors.New("disk on fire")}
	if _, err := a.Flush(t.Context(), failing); err == nil {
		t.Fatal("want the sink error surfaced")
	}
	if got := a.Pending(); got != 1 {
		t.Fatalf("pending = %d, want the batch kept for retry", got)
	}

	// And it must merge with anything added meanwhile rather than replace it.
	a.Add(dnsquery.Query{Time: time.Now(), Client: client, QName: "api.github.com"})
	ok := &fakeSink{}
	if _, err := a.Flush(t.Context(), ok); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	var total int64
	for _, c := range ok.last {
		total += c.Queries
	}
	if total != 2 {
		t.Errorf("queries = %d, want both the retried and the new one", total)
	}
}

func TestFlushEmptyIsNoop(t *testing.T) {
	sink := &fakeSink{err: errors.New("must not be called")}
	n, err := New().Flush(t.Context(), sink)
	if err != nil || n != 0 {
		t.Errorf("Flush on empty = %d, %v", n, err)
	}
}

type fakeSink struct {
	last map[store.Key]store.Counters
	err  error
}

func (f *fakeSink) Bump(_ context.Context, batch map[store.Key]store.Counters) error {
	if f.err != nil {
		return f.err
	}
	f.last = batch
	return nil
}
