package store

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "dnsgate.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func key(client, domain, day string) Key {
	return Key{Client: netip.MustParseAddr(client), Domain: domain, Day: day}
}

func TestBumpAccumulates(t *testing.T) {
	s := openTest(t)
	k := key("192.168.253.123", "github.com", "2026-08-04")
	t0 := time.Date(2026, 8, 4, 10, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 8, 4, 18, 0, 0, 0, time.UTC)

	if err := s.Bump(t.Context(), map[Key]Counters{
		k: {Queries: 3, NXDomain: 1, FirstSeen: t0, LastSeen: t0},
	}); err != nil {
		t.Fatalf("Bump: %v", err)
	}
	if err := s.Bump(t.Context(), map[Key]Counters{
		k: {Queries: 2, Cached: 2, FirstSeen: t1, LastSeen: t1},
	}); err != nil {
		t.Fatalf("Bump: %v", err)
	}

	rows, err := s.Since(t.Context(), "2026-08-01")
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.Queries != 5 || r.NXDomain != 1 || r.Cached != 2 {
		t.Errorf("counters = %+v, want them summed", r.Counters)
	}
	// first_seen must stay at the earliest ever written: "when did this client
	// start talking to this domain" is the question it answers.
	if !r.FirstSeen.Equal(t0) {
		t.Errorf("first_seen = %v, want the earlier %v", r.FirstSeen, t0)
	}
	if !r.LastSeen.Equal(t1) {
		t.Errorf("last_seen = %v, want the later %v", r.LastSeen, t1)
	}
	if r.Client.String() != "192.168.253.123" || r.Domain != "github.com" {
		t.Errorf("key round trip: %+v", r.Key)
	}
}

// Out-of-order arrival must not move first_seen forwards. A late batch is
// normal — sources are polled, and one resolver can lag another.
func TestBumpOutOfOrderKeepsEarliestFirstSeen(t *testing.T) {
	s := openTest(t)
	k := key("192.168.253.1", "example.com", "2026-08-04")
	late := time.Date(2026, 8, 4, 20, 0, 0, 0, time.UTC)
	early := time.Date(2026, 8, 4, 6, 0, 0, 0, time.UTC)

	if err := s.Bump(t.Context(), map[Key]Counters{k: {Queries: 1, FirstSeen: late, LastSeen: late}}); err != nil {
		t.Fatalf("Bump: %v", err)
	}
	if err := s.Bump(t.Context(), map[Key]Counters{k: {Queries: 1, FirstSeen: early, LastSeen: early}}); err != nil {
		t.Fatalf("Bump: %v", err)
	}
	rows, _ := s.Since(t.Context(), "2026-08-01")
	if !rows[0].FirstSeen.Equal(early) {
		t.Errorf("first_seen = %v, want %v", rows[0].FirstSeen, early)
	}
	if !rows[0].LastSeen.Equal(late) {
		t.Errorf("last_seen = %v, want %v", rows[0].LastSeen, late)
	}
}

func TestBumpSeparatesClientsAndDays(t *testing.T) {
	s := openTest(t)
	now := time.Now()
	batch := map[Key]Counters{
		key("192.168.253.1", "github.com", "2026-08-04"):    {Queries: 1, FirstSeen: now, LastSeen: now},
		key("192.168.253.2", "github.com", "2026-08-04"):    {Queries: 1, FirstSeen: now, LastSeen: now},
		key("192.168.253.1", "github.com", "2026-08-05"):    {Queries: 1, FirstSeen: now, LastSeen: now},
		key("192.168.253.1", "datadoghq.com", "2026-08-04"): {Queries: 1, FirstSeen: now, LastSeen: now},
	}
	if err := s.Bump(t.Context(), batch); err != nil {
		t.Fatalf("Bump: %v", err)
	}
	rows, err := s.Since(t.Context(), "2026-08-01")
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if len(rows) != 4 {
		t.Errorf("rows = %d, want 4 distinct buckets", len(rows))
	}
}

func TestSinceFiltersByDay(t *testing.T) {
	s := openTest(t)
	now := time.Now()
	if err := s.Bump(t.Context(), map[Key]Counters{
		key("192.168.253.1", "old.example.com", "2026-07-01"):   {Queries: 1, FirstSeen: now, LastSeen: now},
		key("192.168.253.1", "fresh.example.com", "2026-08-04"): {Queries: 1, FirstSeen: now, LastSeen: now},
	}); err != nil {
		t.Fatalf("Bump: %v", err)
	}
	rows, err := s.Since(t.Context(), "2026-08-01")
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if len(rows) != 1 || rows[0].Domain != "fresh.example.com" {
		t.Errorf("rows = %+v, want only the recent one", rows)
	}
}

// FirstSeenBefore is the primitive the first-seen detector is built on: a
// domain is new exactly when it is absent from this set.
func TestFirstSeenBefore(t *testing.T) {
	s := openTest(t)
	now := time.Now()
	if err := s.Bump(t.Context(), map[Key]Counters{
		key("192.168.253.1", "known.example.com", "2026-08-01"): {Queries: 1, FirstSeen: now, LastSeen: now},
		key("192.168.253.2", "known.example.com", "2026-08-02"): {Queries: 1, FirstSeen: now, LastSeen: now},
		key("192.168.253.1", "new.example.com", "2026-08-04"):   {Queries: 1, FirstSeen: now, LastSeen: now},
	}); err != nil {
		t.Fatalf("Bump: %v", err)
	}
	seen, err := s.FirstSeenBefore(t.Context(), "2026-08-04")
	if err != nil {
		t.Fatalf("FirstSeenBefore: %v", err)
	}
	if _, ok := seen["known.example.com"]; !ok {
		t.Error("known domain missing from the prior set")
	}
	if _, ok := seen["new.example.com"]; ok {
		t.Error("a domain first seen on the day itself must not count as prior")
	}
}

// The cursor is what stops a restart from seeking to the newest row and
// silently skipping everything that arrived while dnsd was down.
func TestCursorRoundTrip(t *testing.T) {
	s := openTest(t)
	got, err := s.LoadCursor(t.Context(), "dnsc1n2")
	if err != nil || got != "" {
		t.Fatalf("unset cursor = %q, %v; want empty", got, err)
	}
	if err := s.SaveCursor(t.Context(), "dnsc1n2", "18047"); err != nil {
		t.Fatalf("SaveCursor: %v", err)
	}
	if err := s.SaveCursor(t.Context(), "dnsc1n2", "18100"); err != nil {
		t.Fatalf("SaveCursor overwrite: %v", err)
	}
	if got, _ := s.LoadCursor(t.Context(), "dnsc1n2"); got != "18100" {
		t.Errorf("cursor = %q, want 18100", got)
	}
	// Sources must not share a cursor: the pair reads two independent logs.
	if got, _ := s.LoadCursor(t.Context(), "dnsc1n1"); got != "" {
		t.Errorf("other source cursor = %q, want empty", got)
	}
}

func TestPrune(t *testing.T) {
	s := openTest(t)
	now := time.Now()
	if err := s.Bump(t.Context(), map[Key]Counters{
		key("192.168.253.1", "a.example.com", "2026-06-01"): {Queries: 1, FirstSeen: now, LastSeen: now},
		key("192.168.253.1", "b.example.com", "2026-08-04"): {Queries: 1, FirstSeen: now, LastSeen: now},
	}); err != nil {
		t.Fatalf("Bump: %v", err)
	}
	n, err := s.Prune(t.Context(), "2026-07-01")
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned %d, want 1", n)
	}
	rows, _ := s.Since(t.Context(), "2000-01-01")
	if len(rows) != 1 || rows[0].Domain != "b.example.com" {
		t.Errorf("remaining = %+v", rows)
	}
}

func TestBumpRejectsInvalidKey(t *testing.T) {
	s := openTest(t)
	if err := s.Bump(t.Context(), map[Key]Counters{
		{Domain: "example.com", Day: "2026-08-04"}: {Queries: 1},
	}); err == nil {
		t.Error("want an error for a key with no client")
	}
	if err := s.Bump(t.Context(), map[Key]Counters{
		key("192.168.253.1", "", "2026-08-04"): {Queries: 1},
	}); err == nil {
		t.Error("want an error for a key with no domain")
	}
}

func TestBumpEmptyIsNoop(t *testing.T) {
	if err := openTest(t).Bump(t.Context(), nil); err != nil {
		t.Errorf("Bump(nil) = %v", err)
	}
}

// Day must be UTC. A store written in local time gets duplicated and
// ambiguous buckets twice a year and sorts wrongly against other offsets.
func TestDayIsUTC(t *testing.T) {
	plus13 := time.FixedZone("NZDT", 13*3600)
	// 2026-08-05 08:00 +13:00 is still 2026-08-04 in UTC.
	if got := Day(time.Date(2026, 8, 5, 8, 0, 0, 0, plus13)); got != "2026-08-04" {
		t.Errorf("Day = %q, want the UTC date 2026-08-04", got)
	}
}

func TestOpenCreatesParentDirectory(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "nested", "dir", "dnsgate.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s.Close()
}

func TestOpenEmptyPath(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Error("want an error for an empty path")
	}
}

func TestReopenKeepsData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnsgate.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	now := time.Now()
	if err := s.Bump(t.Context(), map[Key]Counters{
		key("192.168.253.1", "github.com", "2026-08-04"): {Queries: 7, FirstSeen: now, LastSeen: now},
	}); err != nil {
		t.Fatalf("Bump: %v", err)
	}
	if err := s.SaveCursor(t.Context(), "dnsc1n2", "18047"); err != nil {
		t.Fatalf("SaveCursor: %v", err)
	}
	s.Close()

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	rows, err := reopened.Since(t.Context(), "2026-08-01")
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if len(rows) != 1 || rows[0].Queries != 7 {
		t.Errorf("rows after reopen = %+v", rows)
	}
	if got, _ := reopened.LoadCursor(t.Context(), "dnsc1n2"); got != "18047" {
		t.Errorf("cursor after reopen = %q, want it persisted", got)
	}
}
