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
| `fraudcheckapi.hexbyte.dev`               | Fraud/threat classification for unknown IPs         | Network access required     |

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
