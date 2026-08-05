// Package aggregate turns a stream of individual DNS queries into the daily
// counters dnsgate stores.
//
// The rollup happens in memory and is flushed periodically, because the
// alternative — a write per query — makes storage the dominant cost at 23,000
// queries an hour and answers no question better. Everything downstream asks
// "how much, from whom, to where, and since when", all of which survive
// aggregation.
package aggregate

import (
	"context"
	"sync"
	"time"

	"github.com/kilo666mj/dnsgate/internal/dnsquery"
	"github.com/kilo666mj/dnsgate/internal/store"
)

// Sink is what a flush writes to. store.Store satisfies it.
type Sink interface {
	Bump(ctx context.Context, batch map[store.Key]store.Counters) error
}

// Aggregator folds queries into per-(client, domain, day) counters.
//
// Safe for concurrent use: Add is called from the collector loop while Flush
// may run on a timer.
type Aggregator struct {
	mu    sync.Mutex
	batch map[store.Key]store.Counters
}

// New returns an empty Aggregator.
func New() *Aggregator {
	return &Aggregator{batch: map[store.Key]store.Counters{}}
}

// Add folds one query in. Queries with no usable client are dropped: the
// client address is the identity, and a bucket without one would silently
// merge unrelated hosts. That is the mistake egressgate made by letting
// "unknown" be part of a key, which minted duplicate identities and inflated
// its baseline until convergence was unreachable.
func (a *Aggregator) Add(q dnsquery.Query) {
	if !q.Client.IsValid() || q.QName == "" {
		return
	}

	class := Classify(q.QName)
	when := q.Time
	if when.IsZero() {
		when = time.Now()
	}

	c := store.Counters{Queries: 1, FirstSeen: when, LastSeen: when}
	if q.IsNXDomain() {
		c.NXDomain = 1
	}
	if q.Cached {
		c.Cached = 1
	}
	if q.IsEncrypted() {
		c.Encrypted = 1
	}
	switch class {
	case SingleLabel:
		c.SingleLabel = 1
	case Reverse:
		c.Reverse = 1
	}

	k := store.Key{
		Client: q.Client.Unmap(),
		Domain: Domain(q.QName),
		Day:    store.Day(when),
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	existing := a.batch[k]
	existing.Add(c)
	a.batch[k] = existing
}

// Pending reports how many buckets are waiting to be flushed. Used to decide
// whether a flush is worth doing and to expose progress.
func (a *Aggregator) Pending() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.batch)
}

// Flush writes accumulated counters and clears them.
//
// The batch is detached before the write so Add is never blocked by disk I/O.
// If the write fails the batch is folded back in rather than dropped, so a
// transient database error costs a delay and not an hour of observations.
func (a *Aggregator) Flush(ctx context.Context, sink Sink) (int, error) {
	a.mu.Lock()
	batch := a.batch
	a.batch = map[store.Key]store.Counters{}
	a.mu.Unlock()

	if len(batch) == 0 {
		return 0, nil
	}
	if err := sink.Bump(ctx, batch); err != nil {
		a.restore(batch)
		return 0, err
	}
	return len(batch), nil
}

// restore folds a failed batch back in, merging with anything Add accumulated
// while the write was in flight.
func (a *Aggregator) restore(batch map[store.Key]store.Counters) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, c := range batch {
		existing := a.batch[k]
		existing.Add(c)
		a.batch[k] = existing
	}
}
