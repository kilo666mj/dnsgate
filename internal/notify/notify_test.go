package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"

	"github.com/kilo666mj/dnsgate/internal/detect"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func finding(kind detect.Kind, client string) detect.Finding {
	return detect.Finding{
		Kind: kind, Client: netip.MustParseAddr(client), Day: "2026-08-05",
		Value: 120, Threshold: 60, Queries: 3600,
		TopDomains: []string{"swarm", "swarm.internal"},
		Summary:    client + " is asking 120/min",
	}
}

type capture struct {
	mu   sync.Mutex
	got  []detect.Finding
	fail error
}

func (c *capture) Notify(_ context.Context, f detect.Finding) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return c.fail
	}
	c.got = append(c.got, f)
	return nil
}

func (c *capture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.got)
}

// memSeen is an in-memory Seen for tests that are not about persistence.
type memSeen struct {
	mu   sync.Mutex
	seen map[string]bool
	fail error
}

func newMemSeen() *memSeen { return &memSeen{seen: map[string]bool{}} }

func (m *memSeen) MarkReported(_ context.Context, kind, client, day string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return false, m.fail
	}
	key := kind + "|" + client + "|" + day
	if m.seen[key] {
		return false, nil
	}
	m.seen[key] = true
	return true, nil
}

// The reason this package exists. Detectors run on every flush and a finding
// is a state rather than an event, so without deduplication a noisy client is
// announced every few minutes for the rest of the day — a flood that gets the
// integration muted, which costs more than never having built it.
func TestFindingIsAnnouncedOnce(t *testing.T) {
	to := &capture{}
	r := Reporter{To: to, Seen: newMemSeen(), Log: discardLogger()}

	f := []detect.Finding{finding(detect.KindQueryRate, "192.168.1.50")}
	for range 5 {
		r.Report(t.Context(), f)
	}

	if to.count() != 1 {
		t.Fatalf("delivered %d times, want 1", to.count())
	}
}

func TestReportReturnsWhatItSent(t *testing.T) {
	to := &capture{}
	r := Reporter{To: to, Seen: newMemSeen(), Log: discardLogger()}

	findings := []detect.Finding{
		finding(detect.KindQueryRate, "192.168.1.50"),
		finding(detect.KindNXDomainRate, "192.168.1.51"),
	}
	if n := r.Report(t.Context(), findings); n != 2 {
		t.Fatalf("Report = %d, want 2", n)
	}
	if n := r.Report(t.Context(), findings); n != 0 {
		t.Errorf("Report on a repeat = %d, want 0", n)
	}
}

// Deduplication keyed too coarsely would hide real findings, which is worse
// than the flood it prevents.
func TestDistinctFindingsAreSeparate(t *testing.T) {
	to := &capture{}
	r := Reporter{To: to, Seen: newMemSeen(), Log: discardLogger()}

	sameClient := finding(detect.KindQueryRate, "192.168.1.50")
	otherKind := finding(detect.KindNXDomainRate, "192.168.1.50")
	otherClient := finding(detect.KindQueryRate, "192.168.1.51")
	nextDay := finding(detect.KindQueryRate, "192.168.1.50")
	nextDay.Day = "2026-08-06"

	r.Report(t.Context(), []detect.Finding{sameClient, otherKind, otherClient, nextDay})
	if to.count() != 4 {
		t.Fatalf("delivered %d, want 4 — kind, client and day each distinguish a finding", to.count())
	}
}

// A finding the notifier dropped is not retried: it was already marked. That
// is the deliberate trade — a notifier failing intermittently would otherwise
// produce a duplicate on the next flush for every finding it dropped.
func TestDeliveryFailureIsNotRetried(t *testing.T) {
	to := &capture{fail: errors.New("webhook is down")}
	r := Reporter{To: to, Seen: newMemSeen(), Log: discardLogger()}

	f := []detect.Finding{finding(detect.KindQueryRate, "192.168.1.50")}
	if n := r.Report(t.Context(), f); n != 0 {
		t.Fatalf("Report = %d, want 0 when delivery failed", n)
	}

	to.fail = nil
	if n := r.Report(t.Context(), f); n != 0 {
		t.Errorf("Report = %d, want 0 — the finding was already marked", n)
	}
}

// If the ledger itself cannot be written, send anyway. A duplicate is noise; a
// dropped finding is the thing dnsgate exists to catch.
func TestLedgerFailureStillSends(t *testing.T) {
	to := &capture{}
	seen := newMemSeen()
	seen.fail = errors.New("database is locked")
	r := Reporter{To: to, Seen: seen, Log: discardLogger()}

	r.Report(t.Context(), []detect.Finding{finding(detect.KindQueryRate, "192.168.1.50")})
	if to.count() != 1 {
		t.Errorf("delivered %d, want 1 — a finding must not be lost to a ledger error", to.count())
	}
}

func TestWebhookPayload(t *testing.T) {
	var (
		mu   sync.Mutex
		body []byte
		auth string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		body, auth = b, r.Header.Get("Authorization")
		mu.Unlock()
	}))
	defer srv.Close()

	n := WebhookNotifier{URL: srv.URL, Headers: map[string]string{"Authorization": "Bearer t0ken"}}
	if err := n.Notify(t.Context(), finding(detect.KindSingleLabelLoop, "192.168.1.50")); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if auth != "Bearer t0ken" {
		t.Errorf("Authorization = %q", auth)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	// text is duplicated at the top level so a chat webhook renders something
	// useful without being taught this schema.
	if got["text"] != "192.168.1.50 is asking 120/min" {
		t.Errorf("text = %v", got["text"])
	}
	for _, field := range []string{"kind", "client", "day", "value", "threshold", "queries", "top_domains"} {
		if _, ok := got[field]; !ok {
			t.Errorf("payload has no %q: %v", field, got)
		}
	}
}

func TestWebhookNonSuccessIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	n := WebhookNotifier{URL: srv.URL}
	if err := n.Notify(t.Context(), finding(detect.KindQueryRate, "192.168.1.50")); err == nil {
		t.Error("Notify accepted a 500")
	}
}

// One destination failing must not cost the others — an unreachable webhook
// should not also take out the log line.
func TestNotifiersKeepGoingAfterAFailure(t *testing.T) {
	good := &capture{}
	bad := &capture{fail: errors.New("nope")}
	ns := Notifiers{bad, good}

	err := ns.Notify(t.Context(), finding(detect.KindQueryRate, "192.168.1.50"))
	if err == nil {
		t.Error("Notify hid a failure")
	}
	if good.count() != 1 {
		t.Errorf("the working notifier got %d, want 1", good.count())
	}
}
