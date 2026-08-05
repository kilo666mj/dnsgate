package technitium

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kilo666mj/dnsgate/internal/dnsquery"
)

// liveSample is a verbatim response from dnsc1n2 on 2026-08-04. Decoding the
// real shape matters more than a hand-written fixture: the field names,
// the enum spellings ("Udp", "Cached", "NoError"), the trailing-Z timestamp
// precision and the "A 34.149.66.165" answer format all come from the server.
const liveSample = `{
  "response": {
    "pageNumber": 1,
    "totalPages": 6016,
    "totalEntries": 18047,
    "entries": [
      {
        "rowNumber": 18047,
        "timestamp": "2026-08-04T21:47:15.8392185Z",
        "clientIpAddress": "192.168.253.123",
        "protocol": "Udp",
        "responseType": "Cached",
        "rcode": "NoError",
        "qname": "http-intake.logs.us5.datadoghq.com",
        "qtype": "A",
        "qclass": "IN",
        "answer": "A 34.149.66.165"
      },
      {
        "rowNumber": 18046,
        "timestamp": "2026-08-04T21:47:15.8392128Z",
        "clientIpAddress": "192.168.253.123",
        "protocol": "Udp",
        "responseType": "Recursive",
        "rcode": "NxDomain",
        "qname": "swarm",
        "qtype": "AAAA",
        "qclass": "IN",
        "answer": ""
      }
    ]
  },
  "status": "ok"
}`

func TestDecodeLiveSample(t *testing.T) {
	var env apiEnvelope
	if err := json.Unmarshal([]byte(liveSample), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Response.TotalEntries != 18047 || len(env.Response.Entries) != 2 {
		t.Fatalf("response = %+v", env.Response)
	}

	q, err := env.Response.Entries[0].toQuery("dnsc1n2")
	if err != nil {
		t.Fatalf("toQuery: %v", err)
	}
	if q.QName != "http-intake.logs.us5.datadoghq.com" {
		t.Errorf("qname = %q", q.QName)
	}
	if q.Client.String() != "192.168.253.123" {
		t.Errorf("client = %q", q.Client)
	}
	if !q.Cached {
		t.Error("responseType Cached should set Cached")
	}
	if q.IsNXDomain() {
		t.Error("NoError should not read as NXDOMAIN")
	}
	if len(q.Answers) != 1 || q.Answers[0] != "A 34.149.66.165" {
		t.Errorf("answers = %v", q.Answers)
	}
	if q.Source != "dnsc1n2" {
		t.Errorf("source = %q", q.Source)
	}
	if want := time.Date(2026, 8, 4, 21, 47, 15, 839218500, time.UTC); !q.Time.Equal(want) {
		t.Errorf("time = %v, want %v", q.Time, want)
	}

	// The second entry is the search-domain artifact that turned out to be
	// 46% of this network's DNS traffic.
	nx, err := env.Response.Entries[1].toQuery("dnsc1n2")
	if err != nil {
		t.Fatalf("toQuery: %v", err)
	}
	if !nx.IsNXDomain() {
		t.Error("NxDomain should read as NXDOMAIN")
	}
	if !nx.IsSingleLabel() {
		t.Error(`"swarm" should read as a single-label name`)
	}
	if nx.Cached {
		t.Error("Recursive should not set Cached")
	}
	if len(nx.Answers) != 0 {
		t.Errorf("empty answer should yield no answers, got %v", nx.Answers)
	}
}

func TestQueryNameIsNormalized(t *testing.T) {
	e := entry{
		RowNumber: 1, Timestamp: "2026-08-04T21:47:15Z",
		ClientIPAddress: "192.168.253.10", QName: "Example.COM.", QType: "A", RCode: "NoError",
	}
	q, err := e.toQuery("n1")
	if err != nil {
		t.Fatalf("toQuery: %v", err)
	}
	if q.QName != "example.com" {
		t.Errorf("qname = %q, want lowercased without trailing dot", q.QName)
	}
}

func TestIsEncrypted(t *testing.T) {
	for proto, want := range map[string]bool{
		"Udp": false, "Tcp": false, "Tls": true, "Https": true, "Quic": true,
	} {
		if got := (dnsquery.Query{Protocol: proto}).IsEncrypted(); got != want {
			t.Errorf("%s: IsEncrypted = %v, want %v", proto, got, want)
		}
	}
}

// fakeServer serves rows newest-first with paging, like Technitium does.
func fakeServer(t *testing.T, rows []entry) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "good-token" {
			json.NewEncoder(w).Encode(map[string]any{"status": "invalid-token", "errorMessage": "bad token"})
			return
		}
		per, _ := strconv.Atoi(r.URL.Query().Get("entriesPerPage"))
		page, _ := strconv.Atoi(r.URL.Query().Get("pageNumber"))
		if per <= 0 {
			per = 1000
		}
		total := (len(rows) + per - 1) / per
		start := (page - 1) * per
		end := min(start+per, len(rows))
		var out []entry
		if start < len(rows) {
			out = rows[start:end]
		}
		json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"response": map[string]any{
				"pageNumber": page, "totalPages": total,
				"totalEntries": len(rows), "entries": out,
			},
		})
	}))
}

// rowsDescending builds n rows newest-first, the order the API returns.
func rowsDescending(n int) []entry {
	out := make([]entry, 0, n)
	for i := n; i >= 1; i-- {
		out = append(out, entry{
			RowNumber:       int64(i),
			Timestamp:       time.Date(2026, 8, 4, 12, 0, i, 0, time.UTC).Format(time.RFC3339Nano),
			ClientIPAddress: "192.168.253.10",
			Protocol:        "Udp",
			ResponseType:    "Recursive",
			RCode:           "NoError",
			QName:           fmt.Sprintf("host%d.example.com", i),
			QType:           "A",
		})
	}
	return out
}

func newTestSource(t *testing.T, url string) *Source {
	t.Helper()
	s, err := New(Config{Name: "test", BaseURL: url, Token: "good-token"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// A poll must emit oldest-first even though the API returns newest-first,
// so downstream sees time moving forwards.
func TestPollEmitsOldestFirst(t *testing.T) {
	srv := fakeServer(t, rowsDescending(5))
	defer srv.Close()
	s := newTestSource(t, srv.URL)

	out := make(chan dnsquery.Query, 16)
	n, err := s.poll(t.Context(), out)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n != 5 {
		t.Fatalf("n = %d, want 5", n)
	}
	close(out)

	var got []int64
	for q := range out {
		got = append(got, q.Time.Unix())
	}
	for i := 1; i < len(got); i++ {
		if got[i] < got[i-1] {
			t.Fatalf("not in ascending time order: %v", got)
		}
	}
	if s.cursor != 5 {
		t.Errorf("cursor = %d, want 5", s.cursor)
	}
}

// The cursor is the whole mechanism for not re-reporting queries. A second
// poll with nothing new must emit nothing.
func TestPollIsIncremental(t *testing.T) {
	srv := fakeServer(t, rowsDescending(3))
	defer srv.Close()
	s := newTestSource(t, srv.URL)

	out := make(chan dnsquery.Query, 16)
	if _, err := s.poll(t.Context(), out); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	n, err := s.poll(t.Context(), out)
	if err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if n != 0 {
		t.Errorf("second poll emitted %d, want 0", n)
	}
}

// seek exists so starting dnsd against a resolver with hours of retained
// history does not replay all of it as though it just happened.
func TestSeekSkipsBacklog(t *testing.T) {
	srv := fakeServer(t, rowsDescending(40))
	defer srv.Close()
	s := newTestSource(t, srv.URL)

	if err := s.seek(t.Context()); err != nil {
		t.Fatalf("seek: %v", err)
	}
	if s.cursor != 40 {
		t.Fatalf("cursor = %d, want 40", s.cursor)
	}
	out := make(chan dnsquery.Query, 8)
	n, err := s.poll(t.Context(), out)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n != 0 {
		t.Errorf("poll after seek emitted %d, want 0", n)
	}
}

func TestPollPagesThroughLargeBacklog(t *testing.T) {
	srv := fakeServer(t, rowsDescending(2500))
	defer srv.Close()
	s := newTestSource(t, srv.URL)

	out := make(chan dnsquery.Query, 4096)
	n, err := s.poll(t.Context(), out)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n != 2500 {
		t.Errorf("n = %d, want 2500 across pages", n)
	}
}

// Technitium answers 200 with a status field, so a bad token looks like
// success at the HTTP layer and must be caught explicitly.
func TestBadTokenIsAnError(t *testing.T) {
	srv := fakeServer(t, rowsDescending(1))
	defer srv.Close()
	s, err := New(Config{Name: "test", BaseURL: srv.URL, Token: "wrong"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.poll(t.Context(), make(chan dnsquery.Query, 1)); err == nil {
		t.Fatal("want an error for a bad token")
	}
}

func TestNewValidatesConfig(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no name":  {BaseURL: "http://x:5380", Token: "t"},
		"bad url":  {Name: "n", BaseURL: "://nope", Token: "t"},
		"no token": {Name: "n", BaseURL: "http://x:5380"},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	s, err := New(Config{Name: "n", BaseURL: "http://x:5380", Token: "t"})
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if s.cfg.PollInterval != DefaultPollInterval {
		t.Errorf("poll interval = %v, want default", s.cfg.PollInterval)
	}
}

// A token must never reach a log line. Poll failures are logged on every
// cycle, and those logs get shipped off-host — a token in one is a token in
// whatever collects them.
func TestErrorsDoNotLeakTheToken(t *testing.T) {
	// Nothing listening, so the transport error carries the full request URL.
	s, err := New(Config{Name: "n", BaseURL: "http://127.0.0.1:59999", Token: "super-secret-token"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, pollErr := s.poll(t.Context(), make(chan dnsquery.Query, 1))
	if pollErr == nil {
		t.Fatal("want an error against a dead port")
	}
	msg := pollErr.Error()
	if strings.Contains(msg, "super-secret-token") {
		t.Errorf("error leaks the token: %s", msg)
	}
	if !strings.Contains(msg, "REDACTED") {
		t.Errorf("error should show the redacted URL, got: %s", msg)
	}

	// And the seek path, which runs before the first poll.
	seekErr := s.seek(t.Context())
	if seekErr == nil {
		t.Fatal("want an error from seek")
	}
	if strings.Contains(seekErr.Error(), "super-secret-token") {
		t.Errorf("seek error leaks the token: %s", seekErr)
	}
}
