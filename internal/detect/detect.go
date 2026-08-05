// Package detect holds the operational detectors: the ones that need a
// threshold rather than a converged baseline, and therefore work on the first
// day dnsd runs.
//
// The distinction matters for sequencing. Security detection — a client
// reaching a domain it has never reached before — needs a baseline that has
// been proven to converge, which takes a week of undisturbed collection and
// might fail. Operational detection needs only a number. On 2026-08-04 a
// half-hour sample of this network, examined by hand before any of this
// existed, found one host issuing 46% of all DNS traffic. These detectors are
// that examination, automated.
package detect

import (
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/kilo666mj/dnsgate/internal/store"
)

// Kind identifies what was found.
type Kind string

const (
	// KindQueryRate is a client asking far more than its peers.
	KindQueryRate Kind = "query-rate"

	// KindSingleLabelLoop is search-domain expansion running hot: a bare name
	// tried before the search domain is appended, answering NXDOMAIN every
	// time. Half the cost is pure waste, and it is invisible without looking.
	KindSingleLabelLoop Kind = "single-label-loop"

	// KindNXDomainRate is a client whose lookups mostly fail — a
	// misconfiguration, or a domain-generation algorithm.
	KindNXDomainRate Kind = "nxdomain-rate"
)

// Finding is one thing worth telling someone about.
type Finding struct {
	Kind   Kind
	Client netip.Addr
	Day    string

	// Value is what was measured and Threshold is what it exceeded, both in
	// the detector's own units. Reporting both means the message can say why
	// it fired rather than only that it did.
	Value     float64
	Threshold float64

	// Queries is the volume behind the finding, so a reader can tell a busy
	// client from a broken one.
	Queries int64

	// TopDomains are the biggest contributors, which is usually the whole
	// diagnosis: "swarm, swarm.internal" says search-domain expansion without
	// any further investigation.
	TopDomains []string

	// Summary is a one-line human description.
	Summary string
}

// Thresholds are the limits a Finding is measured against.
type Thresholds struct {
	QueriesPerMinute     float64
	SingleLabelPerMinute float64
	NXDomainRatio        float64
	MinQueries           int64
}

// Run examines observations and returns findings, most severe first.
//
// Rates are computed from the span each client was actually observed over,
// not from the length of the day. A client seen for ten minutes that asked
// 600 times was running at 60/min, and treating that as 0.4/min because the
// day is 24 hours long would hide exactly the bursts worth catching.
func Run(rows []store.Row, th Thresholds) []Finding {
	type acc struct {
		queries, nx, single int64
		first, last         time.Time
		domains             map[string]int64
	}

	byClient := map[string]*acc{}
	clientAddr := map[string]netip.Addr{}

	for _, r := range rows {
		k := r.Client.String() + "|" + r.Day
		a := byClient[k]
		if a == nil {
			a = &acc{domains: map[string]int64{}}
			byClient[k] = a
			clientAddr[k] = r.Client
		}
		a.queries += r.Queries
		a.nx += r.NXDomain
		a.single += r.SingleLabel
		a.domains[r.Domain] += r.Queries
		if a.first.IsZero() || (!r.FirstSeen.IsZero() && r.FirstSeen.Before(a.first)) {
			a.first = r.FirstSeen
		}
		if r.LastSeen.After(a.last) {
			a.last = r.LastSeen
		}
	}

	var out []Finding
	for k, a := range byClient {
		if a.queries < th.MinQueries {
			// Too little traffic to judge. Without this a host that asks
			// twice and misses once reads as a 50% failure rate.
			continue
		}
		client := clientAddr[k]
		day := k[len(client.String())+1:]
		minutes := a.last.Sub(a.first).Minutes()
		if minutes < 1 {
			// A span shorter than a minute makes any rate meaningless and
			// arbitrarily large. Treat it as a minute.
			minutes = 1
		}

		if th.QueriesPerMinute > 0 {
			if rate := float64(a.queries) / minutes; rate > th.QueriesPerMinute {
				out = append(out, Finding{
					Kind: KindQueryRate, Client: client, Day: day,
					Value: rate, Threshold: th.QueriesPerMinute, Queries: a.queries,
					TopDomains: topDomains(a.domains, 3),
					Summary: fmt.Sprintf("%s issued %.0f queries/min (%d total), above %.0f",
						client, rate, a.queries, th.QueriesPerMinute),
				})
			}
		}

		if th.SingleLabelPerMinute > 0 && a.single > 0 {
			if rate := float64(a.single) / minutes; rate > th.SingleLabelPerMinute {
				out = append(out, Finding{
					Kind: KindSingleLabelLoop, Client: client, Day: day,
					Value: rate, Threshold: th.SingleLabelPerMinute, Queries: a.single,
					TopDomains: topDomains(a.domains, 3),
					Summary: fmt.Sprintf("%s made %.0f single-label lookups/min (%d total) — "+
						"search-domain expansion with no caching; each one costs an extra NXDOMAIN",
						client, rate, a.single),
				})
			}
		}

		if th.NXDomainRatio > 0 {
			if ratio := float64(a.nx) / float64(a.queries); ratio > th.NXDomainRatio {
				out = append(out, Finding{
					Kind: KindNXDomainRate, Client: client, Day: day,
					Value: ratio, Threshold: th.NXDomainRatio, Queries: a.queries,
					TopDomains: topDomains(a.domains, 3),
					Summary: fmt.Sprintf("%s: %.0f%% of %d lookups returned NXDOMAIN, above %.0f%%",
						client, ratio*100, a.queries, th.NXDomainRatio*100),
				})
			}
		}
	}

	// Most over its threshold first, so the worst offender leads. Ties break
	// on client then kind so the order is stable across runs — an unstable
	// order makes alert deduplication impossible.
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		ax, bx := a.Value/a.Threshold, b.Value/b.Threshold
		if ax != bx {
			return ax > bx
		}
		if c := a.Client.Compare(b.Client); c != 0 {
			return c < 0
		}
		return a.Kind < b.Kind
	})
	return out
}

func topDomains(counts map[string]int64, n int) []string {
	type kv struct {
		domain string
		count  int64
	}
	all := make([]kv, 0, len(counts))
	for d, c := range counts {
		all = append(all, kv{d, c})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].count != all[j].count {
			return all[i].count > all[j].count
		}
		return all[i].domain < all[j].domain
	})
	if len(all) > n {
		all = all[:n]
	}
	out := make([]string, 0, len(all))
	for _, kv := range all {
		out = append(out, kv.domain)
	}
	return out
}
