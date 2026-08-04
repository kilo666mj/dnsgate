# dnsgate

Passive DNS baselining and query-health monitoring for a homelab.

Everything already watching this network watches **inbound** traffic —
[`sshgate`](https://github.com/kilo666mj/sshgate),
[`tlsgate`](https://github.com/kilo666mj/tlsgate), `blocker`, `web_watcher`.
`egressgate` watches outbound flows, but attributes them by IP and ASN, which
behind a CDN barely narrows anything down. dnsgate supplies the missing half:
**what each client actually asked for**, by reading the resolver rather than
the wire.

> **Status: early.** The source layer works and is tested. The collector,
> store, detectors and report are not written yet. Nothing is deployed.

## Why the resolver

A resolver sees every lookup with its client address, synchronously, before
any connection is opened. That sidesteps the problem egressgate has spent
weeks on — attributing a flow to a process races the socket closing, and
short-lived UDP flows are barely half attributed. There is no such race here.

It also sees things no flow watcher can: an NXDOMAIN storm produces no traffic
at all, and a client using DNS-over-HTTPS to bypass the local resolver looks
like ordinary port 443 from the outside.

## Two kinds of detector

They share a collector but have very different prerequisites, so they ship
separately:

| | needs | examples |
|---|---|---|
| **Operational** | a threshold | query-rate outliers, NXDOMAIN loops, search-domain waste, cache-miss ratio |
| **Security** | a converged baseline | first-seen registrable domain, DoH/DoT bypass, beaconing intervals |

The operational half works the day the collector runs. During the first
half-hour of looking at real data — before any of this existed — one client
turned out to be issuing **46% of all DNS queries on the network**, resolving
a name it should have cached 88 times a minute. Fixing that removed 57% of
total DNS traffic.

## Pluggable resolvers

Nothing downstream knows where queries came from. A source implements:

```go
type Source interface {
    Name() string
    Run(ctx context.Context, out chan<- Query) error
}
```

Push rather than fetch-with-cursor, because a streaming source (dnstap) has no
meaningful cursor to hand back, while a polling source can keep one internally.

`Merge` fans several sources into one consumer, which is also how a
highly-available resolver pair is handled: two sources, one store. A keepalived
failover then needs no special handling — the node that starts answering starts
producing, and nothing in the baseline is per-node.

Implemented:

- **`technitium`** — Technitium DNS Server running the *Query Logs (Sqlite)*
  app, read over its authenticated HTTP API.

Plausible next: pihole (FTL database), dnstap (unbound, BIND, Knot), AdGuard
Home, Blocky.

## Notes from the Technitium source

Worth knowing if you write another source, because they generalise:

- **Read the API, not the database file.** The app's SQLite file is written
  continuously; copying it yields `database disk image is malformed`, and
  reading it in place means running on the resolver itself.
- **It is a ring, not an archive.** The app keeps the newer of `maxLogRecords`
  and `maxLogDays`. On a busy resolver the record cap binds first — at ~23k
  queries/hour, a 10,000-row cap is a **29-minute** window, not the 7 days the
  day setting implies. Poll well inside it.
- **Page newest-first.** Rows are being pruned from the far end while you read,
  so paging forward through an ascending result set shifts under you.
- **Seek before the first poll**, or starting the daemon replays every retained
  row as though it just happened.
- **A bad token returns HTTP 200** with a `status` field, so it looks like
  success at the transport layer.

## Identity

The key is `client_ip`, and **names are display only**.

This is not a preference. During the first survey of this fleet, a PTR record
claimed `192.168.253.123` was `mailtag.internal` when the host was actually
`swarm.internal` — which named the wrong machine and sent an investigation
after the wrong software. egressgate's `PLAN.md` reached the same rule the
expensive way, pulling reverse DNS out of its identity chain after the same
address kept getting different names depending on whether DNS answered.

The general form, borrowed from that document: *a key may contain only values
that are pure functions of the observation plus offline data.* A client address
qualifies. A registrable domain derived from the public suffix list qualifies.
Anything that needs a lookup to succeed does not.

## Building

```sh
go build ./...
go test -race ./...
```

## License

MIT
