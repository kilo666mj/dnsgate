// Command dnsd collects DNS queries from one or more resolvers, rolls them up
// into daily counters, and reports operational problems.
//
// It is not in the query path and cannot break name resolution. It polls the
// resolvers' own logs over HTTP, so it can run anywhere — and should run
// somewhere other than the resolvers themselves, which on this fleet are
// Raspberry Pis already answering every query on the network.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kilo666mj/dnsgate/internal/aggregate"
	"github.com/kilo666mj/dnsgate/internal/config"
	"github.com/kilo666mj/dnsgate/internal/detect"
	"github.com/kilo666mj/dnsgate/internal/dnsquery"
	"github.com/kilo666mj/dnsgate/internal/source/technitium"
	"github.com/kilo666mj/dnsgate/internal/store"
)

// version is overridden at link time with -X main.version=<tag>.
var version = "dev"

func main() {
	var (
		configPath = flag.String("config", "/etc/dnsgate/config.json", "config file path")
		debug      = flag.Bool("debug", false, "verbose logging")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("dnsd", version)
		return
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)

	if err := run(*configPath, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(configPath string, log *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	st, err := store.Open(cfg.Database)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	sources, err := buildSources(cfg, st, log)
	if err != nil {
		return err
	}

	// Cancelled on SIGINT or SIGTERM so a stop flushes rather than discarding
	// whatever has accumulated since the last write.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("starting", "version", version, "db", st.Path(),
		"sources", len(sources), "flush", time.Duration(cfg.FlushInterval))

	agg := aggregate.New()
	queries := make(chan dnsquery.Query, 4096)

	// Sources run until cancelled; Merge returns when they all have.
	merged := make(chan error, 1)
	go func() {
		merged <- dnsquery.Merge(ctx, queries, func(s dnsquery.Source, err error) {
			log.Error("source stopped", "source", s.Name(), "err", err)
		}, sources...)
		close(queries)
	}()

	flush := time.NewTicker(time.Duration(cfg.FlushInterval))
	defer flush.Stop()

	for {
		select {
		case q, ok := <-queries:
			if !ok {
				// Every source has stopped. Flush what is held before
				// returning, or the last interval is lost.
				flushOnce(context.WithoutCancel(ctx), agg, st, cfg, log)
				return <-merged
			}
			agg.Add(q)

		case <-flush.C:
			flushOnce(ctx, agg, st, cfg, log)

		case <-ctx.Done():
			// Deliberately not ctx: it is already cancelled, and the final
			// write must still be allowed to reach the disk.
			flushOnce(context.WithoutCancel(ctx), agg, st, cfg, log)
			log.Info("stopped")
			return nil
		}
	}
}

func buildSources(cfg config.Config, st *store.Store, log *slog.Logger) ([]dnsquery.Source, error) {
	var out []dnsquery.Source
	for _, s := range cfg.Sources {
		switch s.Type {
		case "technitium":
			src, err := technitium.New(technitium.Config{
				Name:         s.Name,
				BaseURL:      s.URL,
				Token:        s.Token,
				PollInterval: time.Duration(s.PollInterval),
				Logger:       log,
				Checkpoint:   checkpoint{st},
			})
			if err != nil {
				return nil, err
			}
			out = append(out, src)
		default:
			// Validate already rejects this; belt and braces so a new type
			// cannot be half-added.
			return nil, fmt.Errorf("source %q: unsupported type %q", s.Name, s.Type)
		}
	}
	return out, nil
}

// flushOnce writes accumulated counters, then reports on what is now stored.
// Errors are logged rather than returned: a transient database problem should
// not stop collection, and the aggregator keeps the batch for the next try.
func flushOnce(ctx context.Context, agg *aggregate.Aggregator, st *store.Store, cfg config.Config, log *slog.Logger) {
	n, err := agg.Flush(ctx, st)
	if err != nil {
		log.Error("flush failed; counters retained for the next attempt", "err", err)
		return
	}
	if n == 0 {
		return
	}
	log.Debug("flushed", "buckets", n)

	if err := report(ctx, st, cfg, log); err != nil {
		log.Error("detector run failed", "err", err)
	}
	if cfg.RetainDays > 0 {
		cutoff := store.Day(time.Now().AddDate(0, 0, -cfg.RetainDays))
		if pruned, err := st.Prune(ctx, cutoff); err != nil {
			log.Error("prune failed", "err", err)
		} else if pruned > 0 {
			log.Info("pruned old observations", "rows", pruned, "before", cutoff)
		}
	}
}

// report runs the operational detectors over today's observations.
//
// Findings go to the log for now. They belong in fleetglass alongside the rest
// of the fleet's health rather than in a new alerting surface of their own,
// which is the next piece of work.
func report(ctx context.Context, st *store.Store, cfg config.Config, log *slog.Logger) error {
	today := store.Day(time.Now())
	rows, err := st.Since(ctx, today)
	if err != nil {
		return err
	}
	findings := detect.Run(rows, detect.Thresholds{
		QueriesPerMinute:     cfg.Thresholds.QueriesPerMinute,
		SingleLabelPerMinute: cfg.Thresholds.SingleLabelPerMinute,
		NXDomainRatio:        cfg.Thresholds.NXDomainRatio,
		MinQueries:           cfg.Thresholds.MinQueries,
	})
	for _, f := range findings {
		log.Warn(f.Summary,
			"kind", f.Kind, "client", f.Client.String(), "day", f.Day,
			"value", f.Value, "threshold", f.Threshold,
			"queries", f.Queries, "top_domains", f.TopDomains)
	}
	return nil
}

// checkpoint adapts the store to what a source needs, so the source package
// depends on an interface it declares rather than on the store.
type checkpoint struct{ st *store.Store }

func (c checkpoint) Load(ctx context.Context, source string) (string, error) {
	return c.st.LoadCursor(ctx, source)
}

func (c checkpoint) Save(ctx context.Context, source, position string) error {
	return c.st.SaveCursor(ctx, source, position)
}
