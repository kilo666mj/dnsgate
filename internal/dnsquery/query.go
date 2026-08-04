// Package dnsquery defines the normalized DNS observation that every resolver
// source produces, and the Source interface they implement.
//
// The point of the seam is that nothing downstream — collapsing to a
// registrable domain, aggregating counters, detecting a query loop — should
// know whether the records came from Technitium's HTTP API, a pihole FTL
// database, a dnstap stream, or a text log being tailed. Sources differ in how
// they are read (polled versus streamed) and in how much they retain; they do
// not differ in what a DNS query is.
package dnsquery

import (
	"context"
	"net/netip"
	"strings"
	"time"
)

// Query is one observed DNS request and its response, normalized across
// sources. Fields a source cannot supply are left zero rather than guessed at:
// a detector that needs Cached must tolerate sources that never set it.
type Query struct {
	// Time is when the resolver handled the query.
	Time time.Time

	// Client is the address the query came from. This is the identity dnsgate
	// keys on: it is a pure function of the observation and always present.
	//
	// Deliberately not a hostname. A PTR lookup can disagree with reality —
	// during the first survey of this fleet, 192.168.253.123's PTR said
	// "mailtag.internal" while the host was actually "swarm.internal", which
	// sent an investigation after the wrong software. Names are for display.
	Client netip.Addr

	// QName is the queried name, lowercased, without a trailing dot.
	QName string

	// QType is the record type, e.g. "A", "AAAA", "PTR".
	QType string

	// RCode is the response code, e.g. "NoError", "NxDomain".
	RCode string

	// Protocol is the transport, e.g. "Udp", "Tcp", "Tls", "Https", "Quic".
	// Anything other than Udp/Tcp means the client used encrypted DNS, which
	// is worth noticing on a network that expects it not to.
	Protocol string

	// Cached reports whether the resolver answered from cache rather than
	// recursing. Sources that cannot distinguish leave it false.
	Cached bool

	// Answers holds the response records as the source rendered them. Used to
	// map an address back to the name it was resolved from; not part of any
	// identity.
	Answers []string

	// Source names the resolver this came from, so a fleet with several
	// resolvers can tell them apart. Set by the collector, not the source.
	Source string
}

// IsNXDomain reports whether the resolver said the name does not exist.
func (q Query) IsNXDomain() bool { return strings.EqualFold(q.RCode, "NxDomain") }

// IsEncrypted reports whether the client used DNS-over-TLS/HTTPS/QUIC. On a
// network whose clients are expected to use plain UDP to a local resolver,
// this is a bypass signal.
func (q Query) IsEncrypted() bool {
	switch strings.ToLower(q.Protocol) {
	case "tls", "https", "quic", "h3":
		return true
	}
	return false
}

// IsSingleLabel reports whether the name has no dot. These are search-domain
// artifacts — "swarm" before the resolver appends "internal" — and are never
// registrable domains, so they are noise for baselining but signal for
// spotting a misconfigured client.
func (q Query) IsSingleLabel() bool { return !strings.Contains(q.QName, ".") }

// Source is a resolver dnsgate reads queries from.
//
// Run streams observations to out until ctx is cancelled, and is expected to
// block for the life of the process. Polled sources (an HTTP API, a SQLite
// ring) loop internally on their own interval; streamed sources (dnstap) read
// their socket. That difference is the implementation's business, which is why
// the interface is push rather than a Fetch-with-cursor: a stream has no
// meaningful cursor to hand back.
//
// A Source is responsible for not re-emitting records it has already emitted,
// including across a restart if it can manage that. Sources backed by a
// bounded ring must poll well inside the retention window; queries that fall
// out of the ring are gone.
type Source interface {
	// Name identifies this resolver in logs and in stored records. It must be
	// stable across restarts — it ends up in the data.
	Name() string

	// Run streams queries until ctx is cancelled. Returning a non-nil error
	// means the source has given up; returning nil means it finished cleanly.
	Run(ctx context.Context, out chan<- Query) error
}

// Merge fans several sources into one stream, which is how a highly-available
// resolver pair is handled: two sources, one consumer, one store. Failover
// then needs no special handling at all — the node that starts answering
// simply starts producing, and the node that stops goes quiet.
//
// Merge returns when every source has returned and their records have been
// forwarded. The first error is returned; the rest are dropped after being
// passed to onError, so one failing resolver cannot take down collection from
// the others.
func Merge(ctx context.Context, out chan<- Query, onError func(Source, error), sources ...Source) error {
	if len(sources) == 0 {
		return nil
	}

	type result struct {
		src Source
		err error
	}
	results := make(chan result, len(sources))

	for _, src := range sources {
		go func(src Source) {
			// Each source gets its own channel so a slow consumer cannot let
			// one source's records interleave badly with another's close.
			ch := make(chan Query, 256)
			done := make(chan error, 1)
			go func() { done <- src.Run(ctx, ch); close(ch) }()

			for q := range ch {
				if q.Source == "" {
					q.Source = src.Name()
				}
				select {
				case out <- q:
				case <-ctx.Done():
					return
				}
			}
			results <- result{src: src, err: <-done}
		}(src)
	}

	var first error
	for range sources {
		select {
		case r := <-results:
			if r.err == nil {
				continue
			}
			if onError != nil {
				onError(r.src, r.err)
			}
			if first == nil {
				first = r.err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return first
}
