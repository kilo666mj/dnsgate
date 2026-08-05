// Package notify delivers findings somewhere a person will see them.
//
// The implementations here are deliberately generic — a log and an HTTP POST.
// Anything that knows about a particular chat product, monitoring system or
// ticket tracker belongs outside this repository: dnsgate should be useful to
// someone running none of the same infrastructure, and a webhook is the seam
// where their own glue attaches.
//
// # Why this needs deduplication and the log did not
//
// Detectors run on every flush, and a finding is a *state* rather than an
// event: a client over the query-rate threshold is over it on every run for
// the rest of the day. Repeating that in a log is untidy. Repeating it into a
// webhook every few minutes is a flood that gets the integration muted, which
// costs more than never having built it.
//
// So a finding is announced once per client, kind and day. The day is the
// natural granularity — it is already the key the store counts against, and
// "this client is still noisy today" is not news whereas "this client is noisy
// again today" is.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kilo666mj/dnsgate/internal/detect"
)

// Notifier delivers a finding.
type Notifier interface {
	Notify(ctx context.Context, f detect.Finding) error
}

// LogNotifier writes findings to a logger. The default, and enough on its own
// for a host whose journal is already shipped somewhere.
type LogNotifier struct {
	Logger *slog.Logger
}

func (n LogNotifier) Notify(_ context.Context, f detect.Finding) error {
	log := n.Logger
	if log == nil {
		log = slog.Default()
	}
	log.Warn(f.Summary,
		"kind", string(f.Kind), "client", f.Client.String(), "day", f.Day,
		"value", f.Value, "threshold", f.Threshold,
		"queries", f.Queries, "top_domains", f.TopDomains)
	return nil
}

// WebhookNotifier POSTs the finding as JSON.
type WebhookNotifier struct {
	URL    string
	Client *http.Client

	// Headers are sent with every request, which is where an authorization
	// token goes. Kept general rather than growing a field per service.
	Headers map[string]string
}

func (n WebhookNotifier) Notify(ctx context.Context, f detect.Finding) error {
	body, err := json.Marshal(struct {
		Kind       string   `json:"kind"`
		Client     string   `json:"client"`
		Day        string   `json:"day"`
		Value      float64  `json:"value"`
		Threshold  float64  `json:"threshold"`
		Queries    int64    `json:"queries"`
		TopDomains []string `json:"top_domains,omitempty"`

		// Duplicated at the top level so a receiver that renders a single
		// field — most chat webhooks — shows something useful without being
		// taught this schema.
		Text string `json:"text"`
	}{
		Kind: string(f.Kind), Client: f.Client.String(), Day: f.Day,
		Value: f.Value, Threshold: f.Threshold, Queries: f.Queries,
		TopDomains: f.TopDomains, Text: f.Summary,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range n.Headers {
		req.Header.Set(k, v)
	}

	client := n.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

// Notifiers delivers to several destinations. One failing does not stop the
// rest: an unreachable webhook must not also cost the log line.
type Notifiers []Notifier

func (ns Notifiers) Notify(ctx context.Context, f detect.Finding) error {
	var errs []string
	for _, n := range ns {
		if err := n.Notify(ctx, f); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d of %d notifiers failed: %s",
			len(errs), len(ns), strings.Join(errs, "; "))
	}
	return nil
}

// Seen records which findings have already been announced. Backed by the
// store rather than by memory: dnsd restarts for deploys and reboots, and an
// in-memory ledger would re-announce every active finding each time — turning
// a routine restart into a burst of alerts about nothing new.
type Seen interface {
	// MarkReported records a finding as announced and reports whether this
	// call was the one that did it. False means someone already had.
	MarkReported(ctx context.Context, kind, client, day string) (bool, error)
}

// Reporter announces findings that have not been announced before.
type Reporter struct {
	To   Notifier
	Seen Seen
	Log  *slog.Logger
}

// Report delivers the findings that are new, and returns how many were sent.
func (r Reporter) Report(ctx context.Context, findings []detect.Finding) int {
	log := r.Log
	if log == nil {
		log = slog.Default()
	}

	var sent int
	for _, f := range findings {
		if r.Seen != nil {
			fresh, err := r.Seen.MarkReported(ctx, string(f.Kind), f.Client.String(), f.Day)
			if err != nil {
				// Marked-but-not-sent loses a finding; sent-but-not-marked
				// repeats one. On a failure to even record the attempt, the
				// safer direction is to say it — a duplicate is noise, a
				// dropped finding is the thing dnsgate exists to catch.
				log.Error("could not record a finding as reported; sending anyway",
					"kind", f.Kind, "client", f.Client.String(), "err", err)
			} else if !fresh {
				continue
			}
		}
		if err := r.To.Notify(ctx, f); err != nil {
			// Already marked, so this is not retried. A notifier that fails
			// intermittently would otherwise produce a duplicate on the next
			// flush for every finding it dropped.
			log.Error("could not deliver finding",
				"kind", f.Kind, "client", f.Client.String(), "err", err)
			continue
		}
		sent++
	}
	return sent
}
