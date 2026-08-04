// Package technitium reads DNS queries from a Technitium DNS Server running
// the "Query Logs (Sqlite)" app, over the server's authenticated HTTP API.
//
// Reading the API rather than the app's SQLite file on disk is deliberate.
// The file is written continuously by the server, so copying it yields a
// torn image ("database disk image is malformed"), and reading it in place
// means running on the resolver itself. The API returns the same rows as
// typed JSON, so one dnsd can poll several resolvers from anywhere.
//
// The query log is a bounded ring, not an archive: the app keeps the newer of
// maxLogRecords rows and maxLogDays days. On a busy resolver the record cap
// binds first — at ~23k queries/hour a 10,000-row cap is a 29-minute window.
// Poll well inside it; whatever ages out is gone.
package technitium

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/kilo666mj/dnsgate/internal/dnsquery"
)

const (
	// DefaultPollInterval is a small fraction of the retention window so a
	// slow cycle, a restart, or a brief outage cannot silently lose queries.
	DefaultPollInterval = 5 * time.Minute

	// entriesPerPage is what each API call asks for. Technitium pages the
	// result set; this trades request count against response size.
	entriesPerPage = 1000

	// maxPagesPerPoll bounds the work of a single cycle so a long outage
	// cannot turn one poll into an unbounded backfill. Anything beyond this
	// has almost certainly aged out of the ring anyway.
	maxPagesPerPoll = 50

	appName      = "Query Logs (Sqlite)"
	appClassPath = "QueryLogsSqlite.App"
)

// Config describes one Technitium server to read from.
type Config struct {
	// Name identifies this resolver in stored records. Stable across
	// restarts; it ends up in the data.
	Name string

	// BaseURL is the web console root, e.g. "http://192.168.253.105:5380".
	BaseURL string

	// Token is an API token created under Administration → Sessions. A token
	// is preferred over a username and password: it can be revoked on its own
	// without rotating the admin credentials.
	Token string

	// PollInterval defaults to DefaultPollInterval.
	PollInterval time.Duration

	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

// Source polls one Technitium server.
type Source struct {
	cfg    Config
	client *http.Client
	log    *slog.Logger

	// cursor is the highest rowNumber already emitted. Technitium's rowNumber
	// is the query log's SQLite rowid, so it increases monotonically and
	// survives the ring pruning older rows underneath us.
	cursor int64
}

// New builds a Source. It does not contact the server.
func New(cfg Config) (*Source, error) {
	if strings.TrimSpace(cfg.Name) == "" {
		return nil, fmt.Errorf("technitium: name is required")
	}
	if _, err := url.ParseRequestURI(cfg.BaseURL); err != nil {
		return nil, fmt.Errorf("technitium %s: base url: %w", cfg.Name, err)
	}
	if strings.TrimSpace(cfg.Token) == "" {
		return nil, fmt.Errorf("technitium %s: token is required", cfg.Name)
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultPollInterval
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Source{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
		log:    cfg.Logger.With("source", cfg.Name),
	}, nil
}

// Name implements dnsquery.Source.
func (s *Source) Name() string { return s.cfg.Name }

// Run polls until ctx is cancelled. A failed cycle is logged and retried on
// the next tick rather than returned: one unreachable resolver in a pair must
// not stop collection from the other.
func (s *Source) Run(ctx context.Context, out chan<- dnsquery.Query) error {
	// Establish the cursor before the first real poll, so starting dnsd does
	// not replay the whole retained ring as though it were new activity.
	if err := s.seek(ctx); err != nil {
		s.log.Warn("could not establish initial cursor; starting from zero", "err", err)
	}

	t := time.NewTicker(s.cfg.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			n, err := s.poll(ctx, out)
			if err != nil {
				s.log.Error("poll failed", "err", err)
				continue
			}
			if n > 0 {
				s.log.Debug("polled", "queries", n, "cursor", s.cursor)
			}
		}
	}
}

// seek moves the cursor to the newest row without emitting anything.
func (s *Source) seek(ctx context.Context) error {
	page, err := s.fetch(ctx, 1, 1)
	if err != nil {
		return err
	}
	if len(page.Entries) > 0 {
		s.cursor = page.Entries[0].RowNumber
	}
	return nil
}

// poll emits every record newer than the cursor, oldest first.
func (s *Source) poll(ctx context.Context, out chan<- dnsquery.Query) (int, error) {
	// Walk newest-first and stop at the cursor. Descending order is what
	// makes this safe against a ring that prunes while we read: rows are
	// disappearing from the far end, so paging forward through an ascending
	// result set would shift under us.
	var fresh []entry
	for page := 1; page <= maxPagesPerPoll; page++ {
		resp, err := s.fetch(ctx, page, entriesPerPage)
		if err != nil {
			return 0, err
		}
		if len(resp.Entries) == 0 {
			break
		}
		done := false
		for _, e := range resp.Entries {
			if e.RowNumber <= s.cursor {
				done = true
				break
			}
			fresh = append(fresh, e)
		}
		if done || page >= resp.TotalPages {
			break
		}
		if len(fresh) > 0 && page == maxPagesPerPoll {
			s.log.Warn("hit page cap; older queries in this gap were dropped",
				"pages", maxPagesPerPoll, "collected", len(fresh))
		}
	}

	// Emit oldest-first so downstream sees time moving forwards.
	for i := len(fresh) - 1; i >= 0; i-- {
		q, err := fresh[i].toQuery(s.cfg.Name)
		if err != nil {
			s.log.Warn("skipping unparseable entry", "row", fresh[i].RowNumber, "err", err)
			continue
		}
		select {
		case out <- q:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	if len(fresh) > 0 {
		s.cursor = fresh[0].RowNumber
	}
	return len(fresh), nil
}

type entry struct {
	RowNumber       int64  `json:"rowNumber"`
	Timestamp       string `json:"timestamp"`
	ClientIPAddress string `json:"clientIpAddress"`
	Protocol        string `json:"protocol"`
	ResponseType    string `json:"responseType"`
	RCode           string `json:"rcode"`
	QName           string `json:"qname"`
	QType           string `json:"qtype"`
	QClass          string `json:"qclass"`
	Answer          string `json:"answer"`
}

func (e entry) toQuery(source string) (dnsquery.Query, error) {
	ts, err := time.Parse(time.RFC3339Nano, e.Timestamp)
	if err != nil {
		return dnsquery.Query{}, fmt.Errorf("timestamp %q: %w", e.Timestamp, err)
	}
	addr, err := netip.ParseAddr(e.ClientIPAddress)
	if err != nil {
		return dnsquery.Query{}, fmt.Errorf("client %q: %w", e.ClientIPAddress, err)
	}

	var answers []string
	if a := strings.TrimSpace(e.Answer); a != "" {
		for _, part := range strings.Split(a, ", ") {
			if part = strings.TrimSpace(part); part != "" {
				answers = append(answers, part)
			}
		}
	}

	return dnsquery.Query{
		Time:     ts,
		Client:   addr.Unmap(),
		QName:    strings.ToLower(strings.TrimSuffix(e.QName, ".")),
		QType:    e.QType,
		RCode:    e.RCode,
		Protocol: e.Protocol,
		// Technitium reports how it answered; "Cached" means it did not
		// recurse. Anything else (Recursive, Authoritative, Blocked) did.
		Cached:  strings.EqualFold(e.ResponseType, "Cached"),
		Answers: answers,
		Source:  source,
	}, nil
}

type queryResponse struct {
	PageNumber   int     `json:"pageNumber"`
	TotalPages   int     `json:"totalPages"`
	TotalEntries int     `json:"totalEntries"`
	Entries      []entry `json:"entries"`
}

type apiEnvelope struct {
	Response     queryResponse `json:"response"`
	Status       string        `json:"status"`
	ErrorMessage string        `json:"errorMessage"`
}

func (s *Source) fetch(ctx context.Context, page, perPage int) (queryResponse, error) {
	u, err := url.Parse(strings.TrimRight(s.cfg.BaseURL, "/") + "/api/logs/query")
	if err != nil {
		return queryResponse{}, err
	}
	q := url.Values{}
	q.Set("token", s.cfg.Token)
	q.Set("name", appName)
	q.Set("classPath", appClassPath)
	q.Set("pageNumber", fmt.Sprint(page))
	q.Set("entriesPerPage", fmt.Sprint(perPage))
	q.Set("descendingOrder", "true")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return queryResponse{}, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return queryResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return queryResponse{}, fmt.Errorf("GET %s returned %s", u.Path, resp.Status)
	}

	var env apiEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return queryResponse{}, fmt.Errorf("decode response: %w", err)
	}
	// Technitium answers 200 with a status field, so a bad token looks like
	// success at the HTTP layer.
	if !strings.EqualFold(env.Status, "ok") {
		msg := env.ErrorMessage
		if msg == "" {
			msg = env.Status
		}
		return queryResponse{}, fmt.Errorf("api error: %s (is the token valid?)", msg)
	}
	return env.Response, nil
}
