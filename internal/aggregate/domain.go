package aggregate

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Classification describes what kind of name was asked for. The categories
// exist because the first half-hour of real data was dominated by names that
// are not destinations at all: search-domain artifacts and reverse lookups
// together outnumbered every real domain on the network.
type Classification int

const (
	// Registrable is an ordinary name with a registrable domain — the only
	// kind that belongs in a baseline.
	Registrable Classification = iota

	// SingleLabel has no dot: "swarm" rather than "swarm.internal". These are
	// what a resolver emits before appending a search domain, so they arrive
	// in pairs with a guaranteed NXDOMAIN. Noise for baselining, but the
	// clearest possible signal of a misconfigured or uncached client — one
	// host doing this at 88/min was 46% of this network's DNS traffic.
	SingleLabel

	// Reverse is a PTR lookup under in-addr.arpa or ip6.arpa. Its "domain"
	// varies with the address being looked up, so baselining it measures how
	// many addresses were resolved, not which services were used.
	Reverse
)

// Classify reports what kind of name this is. It looks only at the name, so
// it cannot fail and cannot depend on a lookup succeeding.
func Classify(qname string) Classification {
	name := normalize(qname)
	switch {
	case name == "":
		return SingleLabel
	case strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa"):
		return Reverse
	case !strings.Contains(name, "."):
		return SingleLabel
	default:
		return Registrable
	}
}

// Domain reduces a name to the unit dnsgate baselines on.
//
// For an ordinary name that is the registrable domain (eTLD+1), which is what
// makes the set finite: telemetry endpoints and CDNs mint a unique subdomain
// per request, so a per-FQDN baseline grows forever and every lookup looks
// like a first sighting. In a 30-minute sample of this network, 197 distinct
// names collapsed to 92 registrable domains.
//
// For names with no registrable form — single labels and reverse lookups — the
// name is returned as-is and the caller is expected to use Classify to keep
// them out of the baseline. They are still counted, because they are the
// operational signal.
//
// The public suffix list is offline data, so this is a pure function of the
// observation: it satisfies the rule egressgate arrived at after four bugs,
// that a key may never depend on a lookup succeeding.
func Domain(qname string) string {
	name := normalize(qname)
	if name == "" {
		return ""
	}
	if c := Classify(name); c != Registrable {
		return name
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		// Happens for a name that is itself a public suffix ("co.uk") or an
		// unlisted TLD used bare. Keeping the name is right: it is stable and
		// still a pure function of the observation.
		return name
	}
	return etld1
}

func normalize(qname string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(qname), "."))
}
