// Package store persists what dnsgate has observed.
//
// It holds counters, not queries. A resolver on this network answers ~23,000
// queries an hour; keeping a row per query would make storage the dominant
// design problem and buy nothing, because every question dnsgate asks is of
// the form "how much did this client ask for this domain, and when did that
// start". So observations are rolled up to (client, domain, day) at write
// time and the raw queries are discarded.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Key identifies one aggregation bucket.
type Key struct {
	// Client is the address that asked. dnsgate keys on the address and never
	// on a name: a PTR record on this fleet claimed 192.168.253.123 was
	// "mailtag.internal" when the host was "swarm.internal".
	Client netip.Addr

	// Domain is the registrable domain (eTLD+1), or the raw name when it has
	// no registrable form — a single-label search-domain artifact.
	Domain string

	// Day is the UTC date, YYYY-MM-DD. Buckets are daily so convergence can
	// be measured as "new domains per day" without keeping timestamps.
	Day string
}

// Counters is what is known about a bucket. Everything is a count except the
// timestamps, so two buckets for the same key merge by addition.
type Counters struct {
	Queries     int64
	NXDomain    int64
	Cached      int64
	Encrypted   int64
	SingleLabel int64
	Reverse     int64

	FirstSeen time.Time
	LastSeen  time.Time
}

// Add merges other into c, which is how the in-memory aggregator folds a
// second observation of the same key.
func (c *Counters) Add(other Counters) {
	c.Queries += other.Queries
	c.NXDomain += other.NXDomain
	c.Cached += other.Cached
	c.Encrypted += other.Encrypted
	c.SingleLabel += other.SingleLabel
	c.Reverse += other.Reverse

	if c.FirstSeen.IsZero() || (!other.FirstSeen.IsZero() && other.FirstSeen.Before(c.FirstSeen)) {
		c.FirstSeen = other.FirstSeen
	}
	if other.LastSeen.After(c.LastSeen) {
		c.LastSeen = other.LastSeen
	}
}

// Store is the observation database.
type Store struct {
	path string
	// db is the writer, pinned to one connection so transactions cannot be
	// handed a different connection mid-flight. reader is a separate WAL pool
	// so reporting queries do not queue behind a flush.
	db     *sql.DB
	reader *sql.DB
}

const maxReaders = 8

// dsn applies pragmas through the connection string. Setting them with a
// one-off Exec against a pooled *sql.DB only configures whichever connection
// happened to serve that statement — a bug found in tlsgate, which had been
// setting busy_timeout and journal_mode that way for months.
func dsn(path string, pragmas ...string) string {
	q := url.Values{}
	for _, p := range pragmas {
		q.Add("_pragma", p)
	}
	return path + "?" + q.Encode()
}

// Open opens, creating the file and its directory if needed.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("empty database path")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dsn(path,
		"busy_timeout=5000", "foreign_keys=ON", "journal_mode=WAL", "synchronous=NORMAL"))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	reader, err := sql.Open("sqlite", dsn(path,
		"busy_timeout=5000", "foreign_keys=ON", "journal_mode=WAL"))
	if err != nil {
		db.Close()
		return nil, err
	}
	reader.SetMaxOpenConns(maxReaders)

	s := &Store{path: path, db: db, reader: reader}
	if err := s.init(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

func (s *Store) Close() error {
	var errs []error
	if s.reader != nil {
		errs = append(errs, s.reader.Close())
	}
	if s.db != nil {
		errs = append(errs, s.db.Close())
	}
	return errors.Join(errs...)
}

func (s *Store) init() error {
	ctx := context.Background()
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS observations (
			client       TEXT NOT NULL,
			domain       TEXT NOT NULL,
			day          TEXT NOT NULL,
			queries      INTEGER NOT NULL DEFAULT 0,
			nxdomain     INTEGER NOT NULL DEFAULT 0,
			cached       INTEGER NOT NULL DEFAULT 0,
			encrypted    INTEGER NOT NULL DEFAULT 0,
			single_label INTEGER NOT NULL DEFAULT 0,
			reverse      INTEGER NOT NULL DEFAULT 0,
			first_seen   TEXT NOT NULL,
			last_seen    TEXT NOT NULL,
			PRIMARY KEY (client, domain, day)
		)`,
		// Reporting reads by day (rates, convergence) and by domain (who else
		// talks to this).
		`CREATE INDEX IF NOT EXISTS idx_observations_day ON observations(day)`,
		`CREATE INDEX IF NOT EXISTS idx_observations_domain ON observations(domain)`,

		// A source's read position, so a restart resumes instead of seeking to
		// the newest row and silently skipping everything that arrived while
		// dnsd was down.
		`CREATE TABLE IF NOT EXISTS cursors (
			source     TEXT PRIMARY KEY,
			position   TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// Bump folds a batch of counters into the store in one transaction. Existing
// rows are incremented; first_seen is kept at the earliest value ever written,
// which is what makes "when did this client start talking to this domain" a
// question the store can answer.
func (s *Store) Bump(ctx context.Context, batch map[Key]Counters) error {
	if len(batch) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO observations (
			client, domain, day, queries, nxdomain, cached, encrypted,
			single_label, reverse, first_seen, last_seen
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(client, domain, day) DO UPDATE SET
			queries      = observations.queries      + excluded.queries,
			nxdomain     = observations.nxdomain     + excluded.nxdomain,
			cached       = observations.cached       + excluded.cached,
			encrypted    = observations.encrypted    + excluded.encrypted,
			single_label = observations.single_label + excluded.single_label,
			reverse      = observations.reverse      + excluded.reverse,
			first_seen   = MIN(observations.first_seen, excluded.first_seen),
			last_seen    = MAX(observations.last_seen, excluded.last_seen)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for k, c := range batch {
		if !k.Client.IsValid() || k.Domain == "" || k.Day == "" {
			return fmt.Errorf("invalid key %+v", k)
		}
		if _, err := stmt.ExecContext(ctx,
			k.Client.String(), k.Domain, k.Day,
			c.Queries, c.NXDomain, c.Cached, c.Encrypted, c.SingleLabel, c.Reverse,
			encodeTime(c.FirstSeen), encodeTime(c.LastSeen),
		); err != nil {
			return fmt.Errorf("bump %s/%s: %w", k.Client, k.Domain, err)
		}
	}
	return tx.Commit()
}

// Row is a stored observation.
type Row struct {
	Key
	Counters
}

// Since returns every observation on or after day (YYYY-MM-DD), oldest first.
func (s *Store) Since(ctx context.Context, day string) ([]Row, error) {
	rows, err := s.reader.QueryContext(ctx, `
		SELECT client, domain, day, queries, nxdomain, cached, encrypted,
		       single_label, reverse, first_seen, last_seen
		FROM observations WHERE day >= ? ORDER BY day, client, domain`, day)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Row
	for rows.Next() {
		var (
			r                   Row
			client, first, last string
		)
		if err := rows.Scan(&client, &r.Domain, &r.Day,
			&r.Queries, &r.NXDomain, &r.Cached, &r.Encrypted,
			&r.SingleLabel, &r.Reverse, &first, &last); err != nil {
			return nil, err
		}
		addr, err := netip.ParseAddr(client)
		if err != nil {
			return nil, fmt.Errorf("stored client %q: %w", client, err)
		}
		r.Client = addr
		if r.FirstSeen, err = decodeTime(first); err != nil {
			return nil, fmt.Errorf("first_seen: %w", err)
		}
		if r.LastSeen, err = decodeTime(last); err != nil {
			return nil, fmt.Errorf("last_seen: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// FirstSeenBefore returns the set of domains already known before day. It is
// the primitive the first-seen detector needs: a domain is new if it does not
// appear here.
func (s *Store) FirstSeenBefore(ctx context.Context, day string) (map[string]struct{}, error) {
	rows, err := s.reader.QueryContext(ctx,
		`SELECT DISTINCT domain FROM observations WHERE day < ?`, day)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]struct{}{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out[d] = struct{}{}
	}
	return out, rows.Err()
}

// LoadCursor returns a source's stored read position, or "" if it has none.
func (s *Store) LoadCursor(ctx context.Context, source string) (string, error) {
	var pos string
	err := s.reader.QueryRowContext(ctx,
		`SELECT position FROM cursors WHERE source = ?`, source).Scan(&pos)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return pos, err
}

// SaveCursor records a source's read position.
func (s *Store) SaveCursor(ctx context.Context, source, position string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cursors (source, position, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(source) DO UPDATE SET
			position = excluded.position, updated_at = excluded.updated_at`,
		source, position, encodeTime(time.Now()))
	return err
}

// Prune deletes observations older than the given day, bounding growth. The
// store is counters, so this is cheap and rarely urgent — a year of a busy
// fleet is thousands of rows, not millions.
func (s *Store) Prune(ctx context.Context, before string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM observations WHERE day < ?`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Day renders a time as the UTC bucket key. Always UTC: a store written in
// local time gets ambiguous and duplicated buckets twice a year, and sorts
// wrongly against anything written in another offset.
func Day(t time.Time) string { return t.UTC().Format("2006-01-02") }

func encodeTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func decodeTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, s)
}
