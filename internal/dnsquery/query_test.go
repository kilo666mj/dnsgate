package dnsquery

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeSource struct {
	name             string
	emit             []Query
	err              error
	blockUntilCancel bool
}

func (f *fakeSource) Name() string { return f.name }

func (f *fakeSource) Run(ctx context.Context, out chan<- Query) error {
	for _, q := range f.emit {
		select {
		case out <- q:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if f.blockUntilCancel {
		<-ctx.Done()
	}
	return f.err
}

func q(name string) Query { return Query{QName: name, Time: time.Now()} }

// Merging is how a resolver pair is handled: two sources, one consumer. This
// is what makes a keepalived failover a non-event — the node that starts
// answering starts producing, and no baseline is per-node.
func TestMergeCombinesSources(t *testing.T) {
	a := &fakeSource{name: "n1", emit: []Query{q("a.example.com"), q("b.example.com")}}
	b := &fakeSource{name: "n2", emit: []Query{q("c.example.com")}}

	out := make(chan Query, 8)
	if err := Merge(t.Context(), out, nil, a, b); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	close(out)

	seen := map[string]string{}
	for got := range out {
		seen[got.QName] = got.Source
	}
	if len(seen) != 3 {
		t.Fatalf("got %d queries, want 3: %v", len(seen), seen)
	}
	if seen["a.example.com"] != "n1" || seen["c.example.com"] != "n2" {
		t.Errorf("source not stamped correctly: %v", seen)
	}
}

// A source that already set Source keeps it — a source reading several
// upstreams may know better than its own name.
func TestMergePreservesExplicitSource(t *testing.T) {
	a := &fakeSource{name: "n1", emit: []Query{{QName: "x.example.com", Source: "upstream-7"}}}
	out := make(chan Query, 4)
	if err := Merge(t.Context(), out, nil, a); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	close(out)
	got := <-out
	if got.Source != "upstream-7" {
		t.Errorf("source = %q, want it preserved", got.Source)
	}
}

// One unreachable resolver must not stop collection from the other, or a
// single Pi rebooting would blind the whole fleet.
func TestMergeSurvivesOneFailingSource(t *testing.T) {
	boom := errors.New("resolver unreachable")
	bad := &fakeSource{name: "n1", err: boom}
	good := &fakeSource{name: "n2", emit: []Query{q("a.example.com"), q("b.example.com")}}

	var mu sync.Mutex
	var failed []string
	out := make(chan Query, 8)
	err := Merge(t.Context(), out, func(s Source, err error) {
		mu.Lock()
		defer mu.Unlock()
		failed = append(failed, s.Name())
	}, bad, good)
	close(out)

	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want the source error surfaced", err)
	}
	var n int
	for range out {
		n++
	}
	if n != 2 {
		t.Errorf("collected %d queries from the healthy source, want 2", n)
	}
	if len(failed) != 1 || failed[0] != "n1" {
		t.Errorf("onError saw %v, want [n1]", failed)
	}
}

func TestMergeNoSources(t *testing.T) {
	if err := Merge(t.Context(), make(chan Query), nil); err != nil {
		t.Errorf("Merge with no sources = %v, want nil", err)
	}
}

func TestMergeStopsOnCancel(t *testing.T) {
	src := &fakeSource{name: "n1", blockUntilCancel: true}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- Merge(ctx, make(chan Query, 1), nil, src) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Merge did not return after cancellation")
	}
}

func TestQueryPredicates(t *testing.T) {
	cases := []struct {
		q                     Query
		nx, encrypted, single bool
	}{
		{Query{RCode: "NxDomain", QName: "swarm", Protocol: "Udp"}, true, false, true},
		{Query{RCode: "NoError", QName: "example.com", Protocol: "Https"}, false, true, false},
		{Query{RCode: "noerror", QName: "a.b.example.com", Protocol: "Tcp"}, false, false, false},
	}
	for i, c := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if got := c.q.IsNXDomain(); got != c.nx {
				t.Errorf("IsNXDomain = %v, want %v", got, c.nx)
			}
			if got := c.q.IsEncrypted(); got != c.encrypted {
				t.Errorf("IsEncrypted = %v, want %v", got, c.encrypted)
			}
			if got := c.q.IsSingleLabel(); got != c.single {
				t.Errorf("IsSingleLabel = %v, want %v", got, c.single)
			}
		})
	}
}
