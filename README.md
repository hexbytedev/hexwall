# pihole-guard

Monitors active network connections and kills any that connect to IPs that are not trusted by Pi-hole history, the built-in local allowlist, or recent already-established traffic — closing the gap that Pi-hole leaves open for direct-IP connections.

---

## The problem

Pi-hole operates at the DNS layer. It can block a domain, but it has no visibility into connections that bypass DNS entirely — processes that dial a hard-coded IP address directly. Malware and compromised packages commonly use this technique to phone home without triggering any DNS-based block.

pihole-guard works from the inverse assumption: **if an IP is not trusted, the connection is suspicious by default.** Trust is granted when the IP matches the built-in CIDR allowlist, was refreshed from Pi-hole query history within the last hour, or was already observed as an established connection within the last 60 seconds. On startup it immediately refreshes trusted IPs from Pi-hole, then refreshes them every 30 seconds while scanning connections every 10 seconds. Anything that falls outside that trust set is checked against an external fraud API. Confirmed threats are either logged (watch mode) or killed (enforce mode).

---

## Dependencies

| Dependency                                | Role                                                | Required                    |
| ----------------------------------------- | --------------------------------------------------- | --------------------------- |
| [`somo`](https://github.com/theopfr/somo) | Lists established TCP/UDP connections; kills by PID | Must be in `$PATH`          |
| Pi-hole FTL database                      | Source of trusted DNS history                       | Auto-detected or via `--db` |
| `deghostapi.hexbyte.dev`                  | Fraud/threat classification for unknown IPs         | Network access required     |

**Build dependency:** `modernc.org/sqlite` (pure-Go SQLite, no CGo or system libsqlite3 required).

---

## Pi-hole database locations

Auto-detection checks in this order:

1. `/etc/pihole/pihole-FTL.db` — bare-metal / package install
2. A running Docker container whose name or image contains `pihole`, inspecting its `/etc/pihole` mount

If neither is found, start fails. Use `--db` to specify the path manually.

---

## CLI flags

| Flag         | Default             | Description                                                      |
| ------------ | ------------------- | ---------------------------------------------------------------- |
| `--db`       | _(auto-detected)_   | Path to `pihole-FTL.db`                                          |
| `--guard-db` | `./pihole-guard.db` | Path to the local guard database (created on first run)          |
| `--mode`     | `watch`             | `watch` — detect and log only; `enforce` — detect, log, and kill |
| `--debug`    | `false`             | Enable verbose per-connection scan logging                       |

`--mode` accepts `watch` or `enforce` (case-insensitive). Any other value exits with an error.

### Debug logging

When `--debug` is enabled, each scan cycle logs every connection it encounters with its status:

- **allowed** — IP is in the local trust cache or allowlist
- **unrecognized-clean** — IP is not in cache, but the fraud API returned a clean verdict (or 403 for private/reserved ranges)
- **vulnerable** — IP is not in cache, fraud API flagged it as abuser/attacker/threat

When debug is disabled (default), only non-allowed results are logged. Additionally, empty scans (somo returning zero connections) are always logged regardless of debug mode.

---

## When a connection is killed

A connection is killed only when all of the following are true:

1. `--mode enforce` is active.
2. `somo` reports the connection as currently established.
3. The remote IP is not trusted.
4. The fraud API returns a report marking the IP as `is_abuser`, `is_attacker`, or `is_threat`.

An IP is considered trusted when any of these are true:

- It matches the built-in CIDR allowlist.
- It was refreshed from Pi-hole history within the last hour.
- It was already seen as an established allowed connection within the last 60 seconds.

Connections are not killed in these cases:

- `--mode watch` is active. The connection is only logged as `would kill`.
- The IP is on the built-in allowlist.
- The IP is still trusted from a recent Pi-hole refresh or recent established-connection activity.
- The fraud API returns HTTP `403`, which is treated as clean/private/reserved.
- The fraud API returns a report but none of `is_abuser`, `is_attacker`, or `is_threat` are true.
- The fraud lookup itself fails.

When a kill does happen, pihole-guard first records the event in the local `killed_connections` audit table and then asks `somo` to kill the owning PID.

---

## How Pi-hole history becomes trusted IPs

Pi-hole trust is built from recent DNS history, not by directly trusting every current connection. The refresh flow is:

1. Read the `queries` table from `pihole-FTL.db`.
2. Select distinct non-empty domains seen within the last hour.
3. Normalize them to lowercase and trim whitespace.
4. Resolve each domain through the system DNS resolver, with bounded concurrency and a 1 second lookup timeout per domain.
5. Ignore domains that do not resolve. This is normal for blocked domains, expired records, and similar cases.
6. Deduplicate resolved IPs. If multiple domains resolve to the same IP, the first domain in sorted order is stored for that IP.
7. Upsert each resolved IP into the local `allowed_ips` table, setting or refreshing `last_refreshed`.

Important details:

- Startup performs this refresh immediately before the first monitoring scan, so normal traffic seen in recent Pi-hole history is trusted before enforcement begins.
- The refresh repeats every 30 seconds.
- Trust from Pi-hole refresh lasts for 1 hour from the most recent successful upsert.
- Existing rows keep their original `first_approved` and `last_established` values when refreshed; only the stored domain and `last_refreshed` timestamp are updated.
- The monitor also extends trust for long-lived allowed connections by updating `last_established` whenever an already-trusted connection is seen still established.

This means an IP becomes trusted from Pi-hole history only after all of these happen:

1. Pi-hole recorded a domain query for it within the last hour.
2. That domain still resolves during a refresh cycle.
3. One of the resolved IPs is written into the local `allowed_ips` cache.

If a domain was seen in Pi-hole history but no longer resolves during refresh, no IP is added for it, so there is nothing to trust from that domain alone.
